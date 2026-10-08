import type { Evidence } from "./types.js";
import {
  evidenceHash,
  validateEvidence,
  verifyEvidenceIntegrity,
} from "./service.js";

export interface EvidenceChainVerification {
  valid: boolean;
  reason: string;
  verifiedCount: number;
  finalHash?: string;
}

export function verifyEvidenceChain(
  chain: Evidence[],
): EvidenceChainVerification {
  let previousHash: string | undefined;

  for (let index = 0; index < chain.length; index += 1) {
    const evidence = chain[index]!;

    try {
      validateEvidence(evidence);
    } catch {
      return {
        valid: false,
        reason: `INVALID_EVIDENCE_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (!verifyEvidenceIntegrity(evidence)) {
      return {
        valid: false,
        reason: `RECORD_HASH_MISMATCH_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (evidence.previousEvidenceHash !== previousHash) {
      return {
        valid: false,
        reason: `PREVIOUS_HASH_MISMATCH_AT_${index}`,
        verifiedCount: index,
      };
    }

    previousHash = evidenceHash(evidence);
  }

  const result: EvidenceChainVerification = {
    valid: true,
    reason: "EVIDENCE_CHAIN_VALID",
    verifiedCount: chain.length,
  };

  if (previousHash !== undefined) {
    result.finalHash = previousHash;
  }

  return result;
}
