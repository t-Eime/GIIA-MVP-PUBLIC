import type { Decision } from "../core/result.js";

/** Lower-level stage result. Never an authoritative consequential decision. */

export interface AuthorizationRequest {
  id: string;
  subjectIdentityId: string;
  authorityId: string;
  action: string;
  resource: string;
  requestedAt: string;
}

export interface AuthorizationResult {
  requestId: string;
  decision: Decision;
  authoritative: false;
  reason: string;
}
