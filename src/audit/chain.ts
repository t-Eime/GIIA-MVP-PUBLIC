import type { AuditEvent } from "./types.js";
import {
  auditHash,
  validateAudit,
  verifyAuditIntegrity,
} from "./service.js";

export interface AuditChainVerification {
  valid: boolean;
  reason: string;
  verifiedCount: number;
  finalHash?: string;
}

export function verifyAuditChain(
  chain: AuditEvent[],
): AuditChainVerification {
  let previousHash: string | undefined;

  for (let index = 0; index < chain.length; index += 1) {
    const event = chain[index]!;

    try {
      validateAudit(event);
    } catch {
      return {
        valid: false,
        reason: `INVALID_AUDIT_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (!verifyAuditIntegrity(event)) {
      return {
        valid: false,
        reason: `RECORD_HASH_MISMATCH_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (event.previousAuditHash !== previousHash) {
      return {
        valid: false,
        reason: `PREVIOUS_HASH_MISMATCH_AT_${index}`,
        verifiedCount: index,
      };
    }

    previousHash = auditHash(event);
  }

  const result: AuditChainVerification = {
    valid: true,
    reason: "AUDIT_CHAIN_VALID",
    verifiedCount: chain.length,
  };

  if (previousHash !== undefined) {
    result.finalHash = previousHash;
  }

  return result;
}
