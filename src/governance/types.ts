import type { Decision } from "../core/result.js";

/** Lower-level stage result. Never an authoritative consequential decision. */

export interface GovernanceRule {
  id: string;
  version: string;
  name: string;
  status: "active" | "revoked" | "expired" | "unknown";
  issuer: string;
  jurisdiction?: string;
  precedence: number;
  effectiveFrom: string;
  effectiveUntil?: string;
  appliesToActions: string[];
  prohibitedActions: string[];
  requiredConditions: string[];
  provenance: string;
  /**
   * Optional at the lower-level governance stage.
   * Authoritative pipeline evaluation requires a valid signature.
   */
  signature?: string;
}

export interface GovernanceRequest {
  id: string;
  subject: string;
  action: string;
  resource: string;
  requestedAt: string;
  jurisdiction?: string;
  satisfiedConditions: string[];
}

export interface GovernanceResult {
  requestId: string;
  decision: Decision;
  authoritative: false;
  reason: string;
  ruleIds: string[];
  governanceVersion: string;
}
