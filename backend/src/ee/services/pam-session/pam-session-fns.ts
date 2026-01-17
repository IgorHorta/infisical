import { TPamSessions } from "@app/db/schemas";
import { logger } from "@app/lib/logger";
import { TKmsServiceFactory } from "@app/services/kms/kms-service";
import { KmsDataKey } from "@app/services/kms/kms-types";

import { TPamSanitizedSession, TPamSessionCommandLog, TTerminalEvent } from "./pam-session-types";

type TLogEntry = TPamSessionCommandLog | TTerminalEvent;

const getTimestamp = (log: TLogEntry): number =>
  log.timestamp instanceof Date ? log.timestamp.getTime() : new Date(log.timestamp).getTime();

const getLogIdentifier = (log: TLogEntry): string => {
  if ("input" in log && log.input !== undefined) return log.input;
  if ("eventType" in log && "data" in log) return `${log.eventType}:${log.data}`;
  return "unknown";
};

/**
 * Merge logs, removing duplicates based on timestamp and input (within 1 second tolerance)
 */
const mergeLogs = (existingLogs: TLogEntry[], newLogs: TPamSessionCommandLog[]): TLogEntry[] => {
  const logMap = new Map<string, TLogEntry>();

  for (const log of [...existingLogs, ...newLogs]) {
    const timestamp = getTimestamp(log);
    const key = `${getLogIdentifier(log)}-${Math.floor(timestamp / 1000)}`;
    const existing = logMap.get(key);

    if (!existing || timestamp > getTimestamp(existing)) {
      logMap.set(key, log);
    }
  }

  return Array.from(logMap.values()).sort((a, b) => getTimestamp(a) - getTimestamp(b));
};

export const decryptSessionCommandLogs = async ({
  projectId,
  encryptedLogs,
  kmsService
}: {
  projectId: string;
  encryptedLogs: Buffer;
  kmsService: Pick<TKmsServiceFactory, "createCipherPairWithDataKey">;
}): Promise<TLogEntry[]> => {
  const { decryptor } = await kmsService.createCipherPairWithDataKey({
    type: KmsDataKey.SecretManager,
    projectId
  });

  const decrypted = decryptor({ cipherTextBlob: encryptedLogs });
  return JSON.parse(decrypted.toString()) as TLogEntry[];
};

export const decryptSession = async (
  session: TPamSessions,
  projectId: string,
  kmsService: Pick<TKmsServiceFactory, "createCipherPairWithDataKey">
): Promise<TPamSanitizedSession> => ({
  ...session,
  logs: session.encryptedLogsBlob
    ? await decryptSessionCommandLogs({ projectId, encryptedLogs: session.encryptedLogsBlob, kmsService })
    : []
});

export const encryptSessionCommandLogs = async ({
  projectId,
  logs,
  kmsService
}: {
  projectId: string;
  logs: TLogEntry[];
  kmsService: Pick<TKmsServiceFactory, "createCipherPairWithDataKey">;
}): Promise<Buffer | null> => {
  if (logs.length === 0) return null;

  const { encryptor } = await kmsService.createCipherPairWithDataKey({
    type: KmsDataKey.SecretManager,
    projectId
  });

  return encryptor({ plainText: Buffer.from(JSON.stringify(logs)) }).cipherTextBlob;
};

type TPamSessionDALForLogs = {
  findById: (id: string) => Promise<TPamSessions | null | undefined>;
  updateById: (id: string, data: { encryptedLogsBlob: Buffer }) => Promise<TPamSessions>;
};

/**
 * Append logs incrementally to a session, merging with existing logs if any
 */
export const appendSessionLogsForUser = async ({
  sessionId,
  logs,
  userId,
  pamSessionDAL,
  kmsService
}: {
  sessionId: string;
  logs: TPamSessionCommandLog[];
  userId: string;
  pamSessionDAL: TPamSessionDALForLogs;
  kmsService: Pick<TKmsServiceFactory, "createCipherPairWithDataKey">;
}): Promise<void> => {
  if (logs.length === 0) return;

  try {
    const session = await pamSessionDAL.findById(sessionId);
    if (!session) {
      logger.warn({ sessionId }, "Session not found, skipping log storage");
      return;
    }

    if (session.userId !== userId) {
      logger.warn({ sessionId }, "User does not own session, skipping log storage");
      return;
    }

    const existingLogs = session.encryptedLogsBlob
      ? await decryptSessionCommandLogs({ projectId: session.projectId, encryptedLogs: session.encryptedLogsBlob, kmsService })
      : [];

    const logsToStore = session.encryptedLogsBlob ? mergeLogs(existingLogs, logs) : logs;

    const encryptedLogsBlob = await encryptSessionCommandLogs({
      projectId: session.projectId,
      logs: logsToStore,
      kmsService
    });

    if (encryptedLogsBlob) {
      await pamSessionDAL.updateById(sessionId, { encryptedLogsBlob });
    }
  } catch (err) {
    logger.error({ err, sessionId }, "Failed to append session logs");
  }
};
