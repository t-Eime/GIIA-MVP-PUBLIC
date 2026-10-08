import { invariant } from "../core/errors.js";
import { canonicalHash } from "../core/canonical.js";
import type { Evidence } from "./types.js";

export function validateEvidence(evidence: Evidence): void {
  invariant(
    evidence.id.trim().length > 0,
    "EVIDENCE_ID_EMPTY",
    "Evidence id is required",
  );
  invariant(
    evidence.subject.trim().length > 0,
    "EVIDENCE_SUBJECT_EMPTY",
    "Evidence subject is required",
  );
  invariant(
    evidence.action.trim().length > 0,
    "EVIDENCE_ACTION_EMPTY",
    "Evidence action is required",
  );
  invariant(
    evidence.source.trim().length > 0,
    "EVIDENCE_SOURCE_EMPTY",
    "Evidence source is required",
  );
  invariant(
    evidence.provenance.trim().length > 0,
    "EVIDENCE_PROVENANCE_EMPTY",
    "Evidence provenance is required",
  );
  invariant(
    evidence.contentHash.trim().length > 0,
    "EVIDENCE_HASH_EMPTY",
    "Evidence content hash is required",
  );
  invariant(
    /^[a-f0-9]{64}$/i.test(evidence.recordHash),
    "EVIDENCE_RECORD_HASH_INVALID",
    "Evidence record hash must be a SHA-256 hexadecimal digest",
  );
}

function integrityPayload(evidence: Evidence): Omit<Evidence, "recordHash"> {
  const { recordHash: _recordHash, ...payload } = evidence;
  return payload;
}

export function evidenceHash(evidence: Evidence): string {
  const { recordHash: _recordHash, ...payload } = evidence;
  return canonicalHash(payload);
}

export function createEvidenceHash(
  evidence: Omit<Evidence, "recordHash">,
): string {
  return canonicalHash(evidence);
}

export function verifyEvidenceIntegrity(evidence: Evidence): boolean {
  try {
    validateEvidence(evidence);
  } catch {
    return false;
  }

  return evidenceHash(evidence) === evidence.recordHash;
}
