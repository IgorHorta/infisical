import type { Knex } from "knex";
import { z } from "zod";

import { PamFoldersSchema } from "@app/db/schemas";
import { EventType } from "@app/ee/services/audit-log/audit-log-types";
import { PamAccountOrderBy, PamAccountView } from "@app/ee/services/pam-account/pam-account-enums";
import { SanitizedAwsIamAccountWithResourceSchema } from "@app/ee/services/pam-resource/aws-iam/aws-iam-resource-schemas";
import { SanitizedKubernetesAccountWithResourceSchema } from "@app/ee/services/pam-resource/kubernetes/kubernetes-resource-schemas";
import { SanitizedMySQLAccountWithResourceSchema } from "@app/ee/services/pam-resource/mysql/mysql-resource-schemas";
import { PamResource } from "@app/ee/services/pam-resource/pam-resource-enums";
import { GatewayAccessResponseSchema } from "@app/ee/services/pam-resource/pam-resource-schemas";
import { SanitizedPostgresAccountWithResourceSchema } from "@app/ee/services/pam-resource/postgres/postgres-resource-schemas";
import { SanitizedRedisAccountWithResourceSchema } from "@app/ee/services/pam-resource/redis/redis-resource-schemas";
import { SanitizedSSHAccountWithResourceSchema } from "@app/ee/services/pam-resource/ssh/ssh-resource-schemas";
import { TPamSessionCommandLog } from "@app/ee/services/pam-session/pam-session-types";
import { BadRequestError } from "@app/lib/errors";
import { removeTrailingSlash } from "@app/lib/fn";
import { logger } from "@app/lib/logger";
import { ms } from "@app/lib/ms";
import { OrderByDirection } from "@app/lib/types";
import { readLimit, writeLimit } from "@app/server/config/rateLimiter";
import { verifyAuth } from "@app/server/plugins/auth/verify-auth";
import { AuthMode } from "@app/services/auth/auth-type";

const SanitizedAccountSchema = z.union([
  SanitizedSSHAccountWithResourceSchema, // ORDER MATTERS
  SanitizedPostgresAccountWithResourceSchema,
  SanitizedMySQLAccountWithResourceSchema,
  SanitizedRedisAccountWithResourceSchema,
  SanitizedKubernetesAccountWithResourceSchema,
  SanitizedAwsIamAccountWithResourceSchema
]);

const ListPamAccountsResponseSchema = z.object({
  accounts: SanitizedAccountSchema.array(),
  folders: PamFoldersSchema.array(),
  totalCount: z.number().default(0),
  folderId: z.string().optional(),
  folderPaths: z.record(z.string(), z.string())
});

// Constants for incremental log persistence
const INCREMENTAL_SAVE_BATCH_SIZE = 10;
const INCREMENTAL_SAVE_INTERVAL_MS = 30000;
const MAX_RETRY_ATTEMPTS = 3;
const INITIAL_RETRY_DELAY_MS = 180000; // 3 minutes
const MAX_COMMAND_LENGTH = 10000;

export const registerPamAccountRouter = async (server: FastifyZodProvider) => {
  server.get(
    "/:accountId/terminal",
    { websocket: true, onRequest: verifyAuth([AuthMode.JWT]) },
    async (connection, req) => {
      const { accountId } = req.params as { accountId: string };
      const { sessionId } = req.query as { sessionId: string };

      // Connection state
      let dbClient: Knex | null = null;
      let proxyCleanup: (() => Promise<void>) | null = null;
      let sessionExpirationTimer: NodeJS.Timeout | null = null;
      let incrementalSaveTimer: NodeJS.Timeout | null = null;
      let isCleanedUp = false;
      let failedAttempts = 0;
      const commandLogs: TPamSessionCommandLog[] = [];
      let lastSavedIndex = 0;

      const saveLogsIncrementally = async () => {
        const unsavedLogs = commandLogs.slice(lastSavedIndex);
        if (unsavedLogs.length === 0) return;

        try {
          await server.services.pamSession.appendLogsForUser(sessionId, unsavedLogs, req.permission);
          lastSavedIndex = commandLogs.length;
        } catch (err) {
          logger.error({ err, sessionId }, "Failed to save incremental logs");
        }
      };

      const cleanup = async () => {
        if (isCleanedUp) return;
        isCleanedUp = true;

        if (sessionExpirationTimer) clearTimeout(sessionExpirationTimer);
        if (incrementalSaveTimer) clearInterval(incrementalSaveTimer);
        sessionExpirationTimer = null;
        incrementalSaveTimer = null;

        await saveLogsIncrementally();
        await server.services.pamTerminal.cleanupTerminalConnection({
          dbClient,
          proxyCleanup,
          sessionId,
          commandLogs: commandLogs.slice(lastSavedIndex),
          actor: req.permission,
          auditLogInfo: req.auditLogInfo,
          orgId: req.permission.orgId
        });
      };

      const sendErrorAndClose = async (errorMsg: string, closeCode = 1008) => {
        try {
          connection.socket.send(JSON.stringify({ error: errorMsg, type: "connection_error" }));
        } catch {
          // Ignore send errors
        }
        await cleanup();
        connection.socket.close(closeCode, errorMsg);
      };

      try {
        // Setup terminal connection
        let terminalConnection;
        try {
          terminalConnection = await server.services.pamTerminal.setupTerminalConnection(
            sessionId,
            accountId,
            req.permission
          );
          dbClient = terminalConnection.dbClient;
          proxyCleanup = terminalConnection.proxyCleanup;
        } catch (err) {
          logger.error({ err, sessionId }, "Terminal connection setup failed");
          await sendErrorAndClose(err instanceof Error ? err.message : "Connection failed");
          return;
        }

        const { session } = await server.services.pamSession.getById(sessionId, req.permission);

        connection.socket.send(
          JSON.stringify({
            type: "connected",
            message: "Connected to PostgreSQL database",
            database: terminalConnection.connectionInfo.database,
            username: terminalConnection.connectionInfo.username
          })
        );

        // Session expiration timer
        if (session.expiresAt) {
          const expirationTime = session.expiresAt.getTime() - Date.now();
          if (expirationTime > 0) {
            const timerDelay = Math.max(expirationTime - 5000, 1000);
            sessionExpirationTimer = setTimeout(async () => {
              await sendErrorAndClose("Session expired", 1000);
            }, timerDelay);
          }
        }

        // Incremental log saving timer
        incrementalSaveTimer = setInterval(saveLogsIncrementally, INCREMENTAL_SAVE_INTERVAL_MS);

        // Handle SQL commands
        connection.socket.on("message", async (data) => {
          try {
            const message = JSON.parse(data.toString()) as { command?: string };
            const { command } = message;

            if (!command || typeof command !== "string") {
              connection.socket.send(JSON.stringify({ error: "Invalid command format", type: "error" }));
              return;
            }

            if (command.length > MAX_COMMAND_LENGTH) {
              connection.socket.send(
                JSON.stringify({ error: `Command too long (max ${MAX_COMMAND_LENGTH} characters)`, type: "error" })
              );
              return;
            }

            const trimmedCommand = command.trim().toLowerCase();

            // Handle exit commands
            if (["\\q", "quit", "exit"].includes(trimmedCommand)) {
              connection.socket.send(JSON.stringify({ type: "exit", message: "Connection closed by user" }));
              await cleanup();
              connection.socket.close(1000, "User requested disconnect");
              return;
            }

            // Handle help command
            if (["help", "\\h"].includes(trimmedCommand)) {
              connection.socket.send(
                JSON.stringify({
                  type: "output",
                  output: `Available commands:
\\h or help - Show this help message
\\q or quit - Close connection
\\dt - List tables
SQL queries - Execute any PostgreSQL SQL query`
                })
              );
              return;
            }

            // Handle \dt command (list tables)
            if (trimmedCommand === "\\dt") {
              try {
                const { rows, columns, rowCount } = await server.services.pamTerminal.listTables(dbClient!);

                connection.socket.send(JSON.stringify({ type: "output", rows, columns, rowCount }));
                commandLogs.push({ input: "\\dt", output: JSON.stringify({ rows, columns, rowCount }), timestamp: new Date() });

                if (commandLogs.length - lastSavedIndex >= INCREMENTAL_SAVE_BATCH_SIZE) {
                  await saveLogsIncrementally();
                }

                await server.services.auditLog.createAuditLog({
                  ...req.auditLogInfo,
                  orgId: req.permission.orgId,
                  projectId: session.projectId,
                  event: {
                    type: EventType.PAM_SESSION_LOGS_UPDATE,
                    metadata: { sessionId, accountName: session.accountName }
                  }
                });
              } catch (err) {
                connection.socket.send(
                  JSON.stringify({ type: "error", error: `Failed to list tables: ${err instanceof Error ? err.message : String(err)}` })
                );
              }
              return;
            }

            // Execute SQL query
            try {
              const result = await server.services.pamTerminal.executeSqlQuery(dbClient!, command, {
                maxRetryAttempts: MAX_RETRY_ATTEMPTS,
                initialRetryDelayMs: INITIAL_RETRY_DELAY_MS,
                onRetry: (attempt, error) => {
                  const retryDelay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt - 1);
                  connection.socket.send(
                    JSON.stringify({
                      type: "error",
                      error: error.message,
                      retryAttempt: attempt,
                      maxRetries: MAX_RETRY_ATTEMPTS,
                      nextRetryDelay: retryDelay
                    })
                  );
                  commandLogs.push({
                    input: command,
                    output: `ERROR (Attempt ${attempt}/${MAX_RETRY_ATTEMPTS}): ${error.message}`,
                    timestamp: new Date()
                  });
                },
                onMaxRetriesExceeded: (error) => {
                  connection.socket.send(
                    JSON.stringify({
                      type: "error",
                      error: `Query failed after ${MAX_RETRY_ATTEMPTS} attempts`,
                      connectionClosing: true
                    })
                  );
                  commandLogs.push({ input: command, output: `ERROR: ${error.message}`, timestamp: new Date() });
                }
              });

              connection.socket.send(
                JSON.stringify({
                  type: "output",
                  rows: result.rows,
                  columns: result.columns,
                  rowCount: result.rowCount,
                  executionTime: result.executionTime
                })
              );

              commandLogs.push({
                input: command,
                output: JSON.stringify({ rows: result.rows, columns: result.columns, rowCount: result.rowCount }),
                timestamp: new Date()
              });

              if (commandLogs.length - lastSavedIndex >= INCREMENTAL_SAVE_BATCH_SIZE) {
                await saveLogsIncrementally();
              }

              await server.services.auditLog.createAuditLog({
                ...req.auditLogInfo,
                orgId: req.permission.orgId,
                projectId: session.projectId,
                event: {
                  type: EventType.PAM_SESSION_LOGS_UPDATE,
                  metadata: { sessionId, accountName: session.accountName }
                }
              });

              failedAttempts = 0;
            } catch (queryError) {
              failedAttempts++;
              if (failedAttempts >= MAX_RETRY_ATTEMPTS) {
                if (dbClient) {
                  try {
                    await dbClient.destroy();
                  } catch {
                    // Ignore destroy errors
                  }
                }
                await cleanup();
                connection.socket.close(1008, "Max retry attempts exceeded");
              }
            }
          } catch (parseError) {
            connection.socket.send(JSON.stringify({ error: "Invalid message format", type: "error" }));
          }
        });

        // Cleanup on close
        connection.socket.on("close", cleanup);
        connection.socket.on("error", (err) => logger.error({ err, sessionId }, "WebSocket error"));
        connection.socket.on("ping", () => connection.socket.pong());
      } catch (err) {
        logger.error({ err, sessionId }, "WebSocket handler error");
        await sendErrorAndClose(err instanceof Error ? err.message : "Internal server error");
      }
    }
  );

  server.route({
    method: "GET",
    url: "/",
    config: {
      rateLimit: readLimit
    },
    schema: {
      description: "List PAM accounts",
      querystring: z.object({
        projectId: z.string().uuid(),
        accountPath: z.string().trim().default("/").transform(removeTrailingSlash),
        accountView: z.nativeEnum(PamAccountView).default(PamAccountView.Flat),
        offset: z.coerce.number().min(0).default(0),
        limit: z.coerce.number().min(1).max(100).default(100),
        orderBy: z.nativeEnum(PamAccountOrderBy).default(PamAccountOrderBy.Name),
        orderDirection: z.nativeEnum(OrderByDirection).default(OrderByDirection.ASC),
        search: z.string().trim().optional(),
        filterResourceIds: z
          .string()
          .transform((val) =>
            val
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean)
          )
          .optional()
      }),
      response: {
        200: ListPamAccountsResponseSchema
      }
    },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async (req) => {
      const { projectId, accountPath, accountView, limit, offset, search, orderBy, orderDirection, filterResourceIds } =
        req.query;

      const { accounts, folders, totalCount, folderId, folderPaths } = await server.services.pamAccount.list({
        actorId: req.permission.id,
        actor: req.permission.type,
        actorAuthMethod: req.permission.authMethod,
        actorOrgId: req.permission.orgId,
        projectId,
        accountPath,
        accountView,
        limit,
        offset,
        search,
        orderBy,
        orderDirection,
        filterResourceIds
      });

      await server.services.auditLog.createAuditLog({
        ...req.auditLogInfo,
        orgId: req.permission.orgId,
        projectId,
        event: {
          type: EventType.PAM_ACCOUNT_LIST,
          metadata: {
            accountCount: accounts.length,
            folderCount: folders.length
          }
        }
      });

      return { accounts, folders, totalCount, folderId, folderPaths } as z.infer<typeof ListPamAccountsResponseSchema>;
    }
  });

  server.route({
    method: "POST",
    url: "/access",
    config: {
      rateLimit: writeLimit
    },
    schema: {
      description: "Access PAM account",
      body: z.object({
        accountPath: z.string().trim(),
        projectId: z.string().uuid(),
        mfaSessionId: z.string().optional(),
        duration: z
          .string()
          .min(1)
          .transform((val, ctx) => {
            const parsedMs = ms(val);

            if (typeof parsedMs !== "number" || parsedMs <= 0) {
              ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: "Invalid duration format. Must be a positive duration (e.g., '1h', '30m', '2d')."
              });
              return z.NEVER;
            }
            return parsedMs;
          })
      }),
      response: {
        200: z.discriminatedUnion("resourceType", [
          // Gateway-based resources (Postgres, MySQL, Redis, SSH)
          GatewayAccessResponseSchema.extend({ resourceType: z.literal(PamResource.Postgres) }),
          GatewayAccessResponseSchema.extend({ resourceType: z.literal(PamResource.MySQL) }),
          GatewayAccessResponseSchema.extend({ resourceType: z.literal(PamResource.Redis) }),
          GatewayAccessResponseSchema.extend({ resourceType: z.literal(PamResource.SSH) }),
          GatewayAccessResponseSchema.extend({ resourceType: z.literal(PamResource.Kubernetes) }),
          // AWS IAM (no gateway, returns console URL)
          z.object({
            sessionId: z.string(),
            resourceType: z.literal(PamResource.AwsIam),
            consoleUrl: z.string().url(),
            metadata: z.record(z.string(), z.string().optional()).optional()
          })
        ])
      }
    },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async (req) => {
      // To prevent type errors when accessing req.auth
      if (req.auth.authMode !== AuthMode.JWT) {
        throw new BadRequestError({ message: "You can only access PAM accounts using JWT auth tokens." });
      }

      const response = await server.services.pamAccount.access(
        {
          actorEmail: req.auth.user.email ?? "",
          actorIp: req.realIp,
          actorName: `${req.auth.user.firstName ?? ""} ${req.auth.user.lastName ?? ""}`.trim(),
          actorUserAgent: req.auditLogInfo.userAgent ?? "",
          accountPath: req.body.accountPath,
          projectId: req.body.projectId,
          duration: req.body.duration,
          mfaSessionId: req.body.mfaSessionId
        },
        req.permission
      );

      await server.services.auditLog.createAuditLog({
        ...req.auditLogInfo,
        orgId: req.permission.orgId,
        projectId: req.body.projectId,
        event: {
          type: EventType.PAM_ACCOUNT_ACCESS,
          metadata: {
            accountId: response.account.id,
            accountPath: req.body.accountPath,
            accountName: response.account.name,
            duration: req.body.duration ? new Date(req.body.duration).toISOString() : undefined
          }
        }
      });

      return response;
    }
  });
};
