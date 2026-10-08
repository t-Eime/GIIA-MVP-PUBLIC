import type { Outcome } from "../core/result.js";

export interface AuditEvent {
  id: string;
  actor: string;
  authorizationRequestId?: string;
  evidenceId?: string;
  action: string;
  resource: string;
  outcome: Outcome;
  occurredAt: string;
  recordedAt: string;
  reason: string;
  provenance: string;
  previousAuditHash?: string;
  recordHash: string;
}
