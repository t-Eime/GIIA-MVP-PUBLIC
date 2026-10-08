import { invariant } from "../core/errors.js";
import { canonicalHash } from "../core/canonical.js";
import type { AuditEvent } from "./types.js";

export function validateAudit(event: AuditEvent): void {
  invariant(
    event.id.trim().length > 0,
    "AUDIT_ID_EMPTY",
    "Audit id is required",
  );
  invariant(
    event.actor.trim().length > 0,
    "AUDIT_ACTOR_EMPTY",
    "Audit actor is required",
  );
  invariant(
    event.action.trim().length > 0,
    "AUDIT_ACTION_EMPTY",
    "Audit action is required",
  );
  invariant(
    event.resource.trim().length > 0,
    "AUDIT_RESOURCE_EMPTY",
    "Audit resource is required",
  );
  invariant(
    event.reason.trim().length > 0,
    "AUDIT_REASON_EMPTY",
    "Audit reason is required",
  );
  invariant(
    event.provenance.trim().length > 0,
    "AUDIT_PROVENANCE_EMPTY",
    "Audit provenance is required",
  );
  invariant(
    /^[a-f0-9]{64}$/i.test(event.recordHash),
    "AUDIT_RECORD_HASH_INVALID",
    "Audit record hash must be a SHA-256 hexadecimal digest",
  );
}

export function auditHash(event: AuditEvent): string {
  const { recordHash: _recordHash, ...payload } = event;
  return canonicalHash(payload);
}

export function createAuditHash(
  event: Omit<AuditEvent, "recordHash">,
): string {
  return canonicalHash(event);
}

export function verifyAuditIntegrity(event: AuditEvent): boolean {
  try {
    validateAudit(event);
  } catch {
    return false;
  }

  return auditHash(event) === event.recordHash;
}
