import { sha256 } from "../core/security.js";
import { canonicalize } from "../core/canonical.js";
import { validateNonEmpty, validateTimestamp } from "../core/validation.js";
import { invariant } from "../core/errors.js";

export type SecurityEventType =
  | "REPLAY_DETECTED"
  | "INTEGRITY_VIOLATION"
  | "SIGNATURE_INVALID"
  | "KEY_COMPROMISE_SUSPECTED"
  | "KEY_COMPROMISE_CONFIRMED"
  | "KEY_QUARANTINED"
  | "KEY_REVOKED"
  | "CONTAINMENT_ACTIVATED"
  | "CONTAINMENT_RELEASED";

export type SecuritySeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ContainmentState =
  | "NONE"
  | "QUARANTINED"
  | "CONTAINED"
  | "RELEASED";

export interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  severity: SecuritySeverity;
  subjectId: string;
  detectedAt: string;
  source: string;
  reason: string;
  provenance: string;
  containment: ContainmentState;
  previousEventHash?: string;
  eventHash: string;
}

export function securityEventPayload(
  event: SecurityEvent,
): Omit<SecurityEvent, "eventHash"> {
  const { eventHash: _eventHash, ...payload } = event;
  return payload;
}

export function createSecurityEventHash(
  event: Omit<SecurityEvent, "eventHash">,
): string {
  return sha256(canonicalize(event));
}

export function createSecurityEvent(
  input: Omit<SecurityEvent, "eventHash" | "previousEventHash"> & {
    previousEventHash?: string;
  },
): SecurityEvent {
  validateNonEmpty(
    input.id,
    "SECURITY_EVENT_ID_EMPTY",
    "Security event id is required",
  );

  validateNonEmpty(
    input.subjectId,
    "SECURITY_EVENT_SUBJECT_EMPTY",
    "Security event subject is required",
  );

  validateNonEmpty(
    input.source,
    "SECURITY_EVENT_SOURCE_EMPTY",
    "Security event source is required",
  );

  validateNonEmpty(
    input.reason,
    "SECURITY_EVENT_REASON_EMPTY",
    "Security event reason is required",
  );

  validateNonEmpty(
    input.provenance,
    "SECURITY_EVENT_PROVENANCE_EMPTY",
    "Security event provenance is required",
  );

  validateTimestamp(
    input.detectedAt,
    "SECURITY_EVENT_TIMESTAMP_INVALID",
    "Security event timestamp is invalid",
  );

  invariant(
    input.containment !== undefined,
    "SECURITY_EVENT_CONTAINMENT_REQUIRED",
    "Security event containment state is required",
  );

  const payload = {
    ...input,
    ...(input.previousEventHash === undefined
      ? {}
      : { previousEventHash: input.previousEventHash }),
  };

  return {
    ...payload,
    eventHash: createSecurityEventHash(payload),
  };
}

export function verifySecurityEvent(event: SecurityEvent): boolean {
  return (
    createSecurityEventHash(securityEventPayload(event)) === event.eventHash
  );
}

export interface SecurityChainVerification {
  valid: boolean;
  reason: string;
  verifiedCount: number;
  finalHash?: string;
}

export function verifySecurityEventChain(
  events: SecurityEvent[],
): SecurityChainVerification {
  let previousHash: string | undefined;

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];

    if (event === undefined) {
      return {
        valid: false,
        reason: `EVENT_MISSING_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (!verifySecurityEvent(event)) {
      return {
        valid: false,
        reason: `EVENT_HASH_MISMATCH_AT_${index}`,
        verifiedCount: index,
      };
    }

    if (event.previousEventHash !== previousHash) {
      return {
        valid: false,
        reason: `PREVIOUS_EVENT_HASH_MISMATCH_AT_${index}`,
        verifiedCount: index,
      };
    }

    previousHash = event.eventHash;
  }

  return {
    valid: true,
    reason: "SECURITY_EVENT_CHAIN_VALID",
    verifiedCount: events.length,
    ...(previousHash === undefined ? {} : { finalHash: previousHash }),
  };
}
