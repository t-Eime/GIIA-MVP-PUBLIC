import { sha256 } from "../core/security.js";
import { canonicalize } from "../core/canonical.js";
import {
  validateNonEmpty,
  validateTimestamp,
} from "../core/validation.js";
import { invariant } from "../core/errors.js";
import type { OfflineEvidence } from "./registry.js";

export type EvidenceIntegrityResult = {
  valid: boolean;
  reason: string;
  verifiedCount: number;
  finalHash?: string;
};

export function offlineEvidencePayload(
  evidence: OfflineEvidence,
): Omit<OfflineEvidence, "evidenceHash"> {
  const { evidenceHash: _evidenceHash, ...payload } = evidence;
  return payload;
}

export function createOfflineEvidenceHash(
  evidence: Omit<OfflineEvidence, "evidenceHash">,
): string {
  return sha256(canonicalize(evidence));
}

export function createOfflineEvidence(
  input: Omit<OfflineEvidence, "evidenceHash" | "reconciled"> & {
    reconciled?: boolean;
  },
): OfflineEvidence {
  validateNonEmpty(
    input.id,
    "OFFLINE_EVIDENCE_ID_EMPTY",
    "Offline evidence id is required",
  );

  validateNonEmpty(
    input.subjectId,
    "OFFLINE_EVIDENCE_SUBJECT_EMPTY",
    "Offline evidence subject is required",
  );

  validateNonEmpty(
    input.evidenceType,
    "OFFLINE_EVIDENCE_TYPE_EMPTY",
    "Offline evidence type is required",
  );

  validateNonEmpty(
    input.payload,
    "OFFLINE_EVIDENCE_PAYLOAD_EMPTY",
    "Offline evidence payload is required",
  );

  validateTimestamp(
    input.recordedAt,
    "OFFLINE_EVIDENCE_TIMESTAMP_INVALID",
    "Offline evidence timestamp is invalid",
  );

  invariant(
    Number.isInteger(input.sequence) && input.sequence >= 0,
    "OFFLINE_EVIDENCE_SEQUENCE_INVALID",
    "Offline evidence sequence must be a non-negative integer",
  );

  return {
    ...input,
    reconciled: input.reconciled ?? false,
    evidenceHash: createOfflineEvidenceHash({
      ...input,
      reconciled: input.reconciled ?? false,
    }),
  };
}

export function verifyOfflineEvidence(
  evidence: OfflineEvidence,
): boolean {
  return (
    createOfflineEvidenceHash(
      offlineEvidencePayload(evidence),
    ) === evidence.evidenceHash
  );
}

export function verifyOfflineEvidenceChain(
  evidence: OfflineEvidence[],
): EvidenceIntegrityResult {
  let previousHash: string | undefined;
  let previousSequence = -1;

  for (let index = 0; index < evidence.length; index += 1) {
    const item = evidence[index];

    if (item === undefined) {
      return {
        valid: false,
        reason: `EVIDENCE_MISSING_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (!verifyOfflineEvidence(item)) {
      return {
        valid: false,
        reason: `EVIDENCE_HASH_MISMATCH_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (item.sequence !== previousSequence + 1) {
      return {
        valid: false,
        reason: `EVIDENCE_SEQUENCE_GAP_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (item.previousEvidenceHash !== previousHash) {
      return {
        valid: false,
        reason: `EVIDENCE_PREVIOUS_HASH_MISMATCH_AT_${index}`,
        verifiedCount: index,
      };
    }

    previousHash = item.evidenceHash;
    previousSequence = item.sequence;
  }

  return {
    valid: true,
    reason: "OFFLINE_EVIDENCE_CHAIN_VALID",
    verifiedCount: evidence.length,
    ...(previousHash === undefined
      ? {}
      : { finalHash: previousHash }),
  };
}
