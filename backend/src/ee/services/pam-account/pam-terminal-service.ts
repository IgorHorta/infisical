import type { Knex } from "knex";
import knex from "knex";
import tls, { PeerCertificate } from "tls";

import { AuditLogInfo, EventType, TAuditLogServiceFactory } from "@app/ee/services/audit-log/audit-log-types";
import { TGatewayV2ServiceFactory } from "@app/ee/services/gateway-v2/gateway-v2-service";
import { decryptAccountCredentials } from "@app/ee/services/pam-account/pam-account-fns";
import { TPamAccountDALFactory } from "@app/ee/services/pam-account/pam-account-dal";
import { decryptResourceConnectionDetails } from "@app/ee/services/pam-resource/pam-resource-fns";
import { PamResource } from "@app/ee/services/pam-resource/pam-resource-enums";
import { TPamResourceDALFactory } from "@app/ee/services/pam-resource/pam-resource-dal";
import {
  TSqlAccountCredentials,
  TSqlResourceConnectionDetails
} from "@app/ee/services/pam-resource/shared/sql/sql-resource-types";
import { TPamSessionServiceFactory } from "@app/ee/services/pam-session/pam-session-service";
import { TPamSessionCommandLog } from "@app/ee/services/pam-session/pam-session-types";
import { BadRequestError, NotFoundError } from "@app/lib/errors";
import { GatewayProxyProtocol } from "@app/lib/gateway";
import { setupRelayServer } from "@app/lib/gateway-v2/gateway-v2";
import { logger } from "@app/lib/logger";
import { OrgServiceActor } from "@app/lib/types";
import { TKmsServiceFactory } from "@app/services/kms/kms-service";

type TPamTerminalServiceFactoryDep = {
  pamAccountDAL: TPamAccountDALFactory;
  pamResourceDAL: TPamResourceDALFactory;
  pamSessionService: Pick<TPamSessionServiceFactory, "getById" | "appendLogsForUser" | "endSessionById">;
  auditLogService: TAuditLogServiceFactory;
  kmsService: TKmsServiceFactory;
  gatewayV2Service: TGatewayV2ServiceFactory;
};

export type TPamTerminalServiceFactory = ReturnType<typeof pamTerminalServiceFactory>;

export type TTerminalConnection = {
  dbClient: Knex;
  proxyCleanup: () => Promise<void>;
  connectionInfo: {
    database: string;
    username: string;
  };
};

/**
 * Service for managing PostgreSQL terminal connections via WebSocket
 * Handles session validation, credential decryption, gateway proxy setup, and SQL query execution
 */
export const pamTerminalServiceFactory = ({
  pamAccountDAL,
  pamResourceDAL,
  pamSessionService,
  auditLogService,
  kmsService,
  gatewayV2Service
}: TPamTerminalServiceFactoryDep) => {
  /**
   * Validate terminal connection request and setup database connection
   * Returns connection objects for WebSocket handler to use
   */
  const setupTerminalConnection = async (
    sessionId: string,
    accountId: string,
    actor: OrgServiceActor
  ): Promise<TTerminalConnection> => {
    // Step 1: Get and validate session
    const sessionResult = await pamSessionService.getById(sessionId, actor);
    const session = sessionResult.session;

    if (!session || !session.accountId) {
      throw new NotFoundError({ message: "Session not found" });
    }

    // Verify session matches accountId
    if (session.accountId !== accountId) {
      throw new BadRequestError({ message: "Session does not match account" });
    }

    // Verify session ownership - prevent session hijacking
    if (session.userId !== actor.id) {
      throw new BadRequestError({ message: "You do not have access to this session" });
    }

    // Check session expiration
    const now = new Date();
    if (session.endedAt) {
      throw new BadRequestError({ message: "Session has ended" });
    }

    if (session.expiresAt && session.expiresAt < now) {
      throw new BadRequestError({ message: "Session expired" });
    }

    // Verify resource type is PostgreSQL
    if (session.resourceType !== PamResource.Postgres) {
      throw new BadRequestError({ message: "Terminal access is only supported for PostgreSQL resources" });
    }

    // Step 2: Get account and resource
    const account = await pamAccountDAL.findById(session.accountId);
    if (!account) {
      throw new NotFoundError({ message: `Account with ID '${session.accountId}' not found` });
    }

    const resource = await pamResourceDAL.findById(account.resourceId);
    if (!resource) {
      throw new NotFoundError({ message: `Resource with ID '${account.resourceId}' not found` });
    }

    if (resource.resourceType !== PamResource.Postgres) {
      throw new BadRequestError({ message: `Resource is not a PostgreSQL resource (type: ${resource.resourceType})` });
    }

    if (!resource.gatewayId) {
      throw new BadRequestError({ message: "Resource does not have a gateway configured" });
    }

    // Step 3: Decrypt credentials
    const accountCredentials = await decryptAccountCredentials({
      encryptedCredentials: account.encryptedCredentials,
      projectId: session.projectId,
      kmsService
    }) as TSqlAccountCredentials;

    const connectionDetails = await decryptResourceConnectionDetails<TSqlResourceConnectionDetails>({
      encryptedConnectionDetails: resource.encryptedConnectionDetails,
      projectId: session.projectId,
      kmsService
    });

    // Step 4: Get gateway connection details
    const expiresAt = session.expiresAt || new Date(now.getTime() + 3600000);
    const duration = Math.max(expiresAt.getTime() - now.getTime(), 60000);

    const gatewayConnectionDetails = await gatewayV2Service.getPAMConnectionDetails({
      gatewayId: resource.gatewayId,
      duration,
      sessionId: session.id,
      resourceType: PamResource.Postgres,
      host: connectionDetails.host,
      port: connectionDetails.port,
      actorMetadata: {
        id: actor.id,
        type: actor.type,
        name: actor.id || ""
      }
    });

    if (!gatewayConnectionDetails) {
      throw new NotFoundError({ message: `Gateway connection details for gateway '${resource.gatewayId}' not found` });
    }

    // Step 5: Set up persistent gateway proxy server
    const proxyServer = await setupRelayServer({
      protocol: GatewayProxyProtocol.Tcp,
      relayHost: gatewayConnectionDetails.relayHost,
      gateway: {
        clientCertificate: gatewayConnectionDetails.gateway.clientCertificate,
        clientPrivateKey: gatewayConnectionDetails.gateway.clientPrivateKey,
        serverCertificateChain: gatewayConnectionDetails.gateway.serverCertificateChain
      },
      relay: {
        clientCertificate: gatewayConnectionDetails.relay.clientCertificate,
        clientPrivateKey: gatewayConnectionDetails.relay.clientPrivateKey,
        serverCertificateChain: gatewayConnectionDetails.relay.serverCertificateChain
      }
    });

    logger.debug({ proxyPort: proxyServer.port, sessionId }, "Gateway proxy established");

    // Step 6: Create PostgreSQL connection
    // Calculate session remaining time to respect PAM authorization expiration
    const sessionRemainingMs = Math.max(expiresAt.getTime() - now.getTime(), 60000); // Minimum 1 minute

    const dbClient = knex({
      client: "pg",
      connection: {
        host: "localhost",
        port: proxyServer.port,
        user: accountCredentials.username,
        password: accountCredentials.password,
        database: connectionDetails.database,
        connectionTimeoutMillis: 10000, // Initial connection timeout (10s is fine for localhost proxy)
        ssl: connectionDetails.sslEnabled
          ? {
              rejectUnauthorized: connectionDetails.sslRejectUnauthorized,
              ca: connectionDetails.sslCertificate,
              servername: connectionDetails.host,
              checkServerIdentity: (hostname: string, cert: PeerCertificate) => {
                return tls.checkServerIdentity(connectionDetails.host, cert);
              }
            }
          : false
      },
      pool: {
        min: 0,
        max: 1, // Single connection for terminal session
        // Respect PAM session expiration - close idle connections before session expires
        idleTimeoutMillis: Math.min(sessionRemainingMs - 5000, 300000), // At most 5 minutes, but no longer than session
        // Connection lifetime should not exceed session expiration
        acquireTimeoutMillis: Math.min(sessionRemainingMs, 30000) // Cap at 30s for acquisition
      }
    });

    // Test connection - cleanup proxy if connection fails
    try {
      await dbClient.raw("SELECT 1");
    } catch (err) {
      // Cleanup proxy server if database connection test fails
      await proxyServer.cleanup();
      await dbClient.destroy();
      throw err;
    }

    logger.debug({ sessionId }, "PostgreSQL connection established");

    return {
      dbClient,
      proxyCleanup: proxyServer.cleanup,
      connectionInfo: {
        database: connectionDetails.database,
        username: accountCredentials.username
      }
    };
  };

  /**
   * Execute SQL query with retry logic and exponential backoff
   */
  const executeSqlQuery = async (
    dbClient: Knex,
    command: string,
    options: {
      maxRetryAttempts?: number;
      initialRetryDelayMs?: number;
      onRetry?: (attempt: number, error: Error) => void;
      onMaxRetriesExceeded?: (error: Error) => void;
    } = {}
  ) => {
    const { maxRetryAttempts = 3, initialRetryDelayMs = 1000, onRetry, onMaxRetriesExceeded } = options;

    const executeWithRetry = async (
      attempt = 0
    ): Promise<{ rows: unknown[]; columns: string[]; rowCount: number; executionTime: number }> => {
      const startTime = Date.now();

      try {
        const result = await dbClient.raw(command);
        const executionTime = Date.now() - startTime;
        const rows = Array.isArray(result.rows) ? result.rows : [];
        const columns = rows.length > 0 ? Object.keys(rows[0] as object) : [];

        return { rows, columns, rowCount: rows.length || result.rowCount || 0, executionTime };
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        const currentAttempt = attempt + 1;
        const retryDelay = initialRetryDelayMs * Math.pow(2, currentAttempt - 1);

        logger.warn({ error: error.message, attempt: currentAttempt }, "SQL query failed");

        if (currentAttempt >= maxRetryAttempts) {
          onMaxRetriesExceeded?.(error);
          throw error;
        }

        onRetry?.(currentAttempt, error);
        await new Promise((resolve) => setTimeout(resolve, retryDelay));

        return executeWithRetry(currentAttempt);
      }
    };

    return executeWithRetry();
  };

  /**
   * List tables in PostgreSQL database (equivalent to \dt command)
   */
  const listTables = async (dbClient: Knex) => {
    const query = `
      SELECT table_schema, table_name, table_type
      FROM information_schema.tables
      WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
      ORDER BY table_schema, table_name
    `;

    const result = await dbClient.raw(query);
    const rows = (result.rows || []) as unknown[];

    return { rows, columns: ["table_schema", "table_name", "table_type"], rowCount: rows.length };
  };

  /**
   * Cleanup terminal connection and session resources
   */
  const cleanupTerminalConnection = async ({
    dbClient,
    proxyCleanup,
    sessionId,
    commandLogs,
    actor,
    auditLogInfo,
    orgId
  }: {
    dbClient: Knex | null;
    proxyCleanup: (() => Promise<void>) | null;
    sessionId: string;
    commandLogs: TPamSessionCommandLog[];
    actor: OrgServiceActor;
    auditLogInfo: AuditLogInfo;
    orgId: string;
  }): Promise<void> => {
    // Store remaining logs
    if (commandLogs.length > 0) {
      try {
        await pamSessionService.appendLogsForUser(sessionId, commandLogs, actor);
      } catch (err) {
        logger.error({ err, sessionId }, "Failed to store session logs");
      }
    }

    // End session and create audit log
    try {
      const { session: endedSession, projectId } = await pamSessionService.endSessionById(sessionId, actor);

      await auditLogService.createAuditLog({
        ...auditLogInfo,
        orgId,
        projectId,
        event: {
          type: EventType.PAM_SESSION_END,
          metadata: { sessionId, accountName: endedSession.accountName }
        }
      });
    } catch (err) {
      if (!(err instanceof NotFoundError) && !(err instanceof BadRequestError)) {
        logger.error({ err, sessionId }, "Failed to end session");
      }
    }

    // Close database connection
    if (dbClient) {
      try {
        await dbClient.destroy();
      } catch (err) {
        logger.error({ err, sessionId }, "Failed to close database connection");
      }
    }

    // Cleanup proxy server
    if (proxyCleanup) {
      try {
        await proxyCleanup();
      } catch (err) {
        logger.error({ err, sessionId }, "Failed to cleanup proxy server");
      }
    }
  };

  return {
    setupTerminalConnection,
    executeSqlQuery,
    listTables,
    cleanupTerminalConnection
  };
};