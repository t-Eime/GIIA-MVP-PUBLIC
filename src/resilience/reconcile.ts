import { sha256 } from "../core/security.js";
import { canonicalize } from "../core/canonical.js";
import {
  validateNonEmpty,
  validateTimestamp,
} from "../core/validation.js";
import { invariant } from "../core/errors.js";
import type {
  OfflineEvidence,
  ReconciliationConflict,
} from "./registry.js";
import { verifyOfflineEvidence } from "./evidence.js";

export type ReconciliationResult = {
  accepted: OfflineEvidence[];
  duplicates: string[];
  conflicts: ReconciliationConflict[];
  requiresDefer: boolean;
};

export function evidenceIdentity(
  evidence: OfflineEvidence,
): string {
  return sha256(
    canonicalize({
      subjectId: evidence.subjectId,
      sequence: evidence.sequence,
      evidenceHash: evidence.evidenceHash,
    }),
  );
}

export function reconcileOfflineEvidence(
  local: OfflineEvidence[],
  remote: OfflineEvidence[],
  detectedAt: string,
): ReconciliationResult {
  validateTimestamp(
    detectedAt,
    "RECONCILIATION_TIMESTAMP_INVALID",
    "Reconciliation timestamp is invalid",
  );

  for (const item of [...local, ...remote]) {
    if (!verifyOfflineEvidence(item)) {
      throw new Error(
        `RECONCILIATION_EVIDENCE_INTEGRITY_FAILURE:${item.id}`,
      );
    }
  }

  const accepted: OfflineEvidence[] = [];
  const duplicates: string[] = [];
  const conflicts: ReconciliationConflict[] = [];

  const remoteBySequence = new Map<string, OfflineEvidence>();

  for (const item of remote) {
    remoteBySequence.set(
      `${item.subjectId}:${item.sequence}`,
      item,
    );
  }

  for (const item of local) {
    validateNonEmpty(
      item.subjectId,
      "RECONCILIATION_SUBJECT_EMPTY",
      "Reconciliation subject is required",
    );

    const key = `${item.subjectId}:${item.sequence}`;
    const remoteItem = remoteBySequence.get(key);

    if (remoteItem === undefined) {
      accepted.push(item);
      continue;
    }

    if (remoteItem.evidenceHash === item.evidenceHash) {
      duplicates.push(item.id);
      continue;
    }

    const conflict: ReconciliationConflict = {
      id: `conflict-${evidenceIdentity(item)}`,
      subjectId: item.subjectId,
      localEvidenceId: item.id,
      remoteEvidenceId: remoteItem.id,
      reason:
        "SAME_SUBJECT_AND_SEQUENCE_DIFFERENT_EVIDENCE_HASH",
      detectedAt,
      resolved: false,
    };

    conflicts.push(conflict);
  }

  invariant(
    conflicts.every((conflict) => !conflict.resolved),
    "RECONCILIATION_CONFLICT_AUTO_RESOLVED",
    "Reconciliation conflicts must not be silently resolved",
  );

  return {
    accepted,
    duplicates,
    conflicts,
    requiresDefer: conflicts.length > 0,
  };
}
