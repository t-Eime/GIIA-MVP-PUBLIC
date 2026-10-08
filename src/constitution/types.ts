import type { Decision } from "../core/result.js";

/** Lower-level stage result. Never an authoritative consequential decision. */

export type ConstitutionalScope =
  | "global"
  | "jurisdiction"
  | "domain"
  | "organization";

export type ConstitutionalRuleStatus =
  | "active"
  | "revoked"
  | "expired"
  | "suspended"
  | "unknown";

export interface ConstitutionalRule {
  id: string;
  version: string;
  name: string;
  scope: ConstitutionalScope;
  jurisdiction?: string;
  issuer: string;
  precedence: number;
  effectiveFrom: string;
  effectiveUntil?: string;
  appliesToActions: string[];
  prohibitedActions: string[];
  requiredConditions: string[];
  immutablePrinciples: string[];
  provenance: string;
  status: ConstitutionalRuleStatus;
  signature: string;
}

export interface ConstitutionalRequest {
  id: string;
  subject: string;
  action: string;
  resource: string;
  requestedAt: string;
  jurisdiction?: string;
  satisfiedConditions: string[];
}

export interface ConstitutionalResult {
  requestId: string;
  decision: Decision;
  authoritative: false;
  reason: string;
  ruleIds: string[];
  constitutionalVersion: string;
  scope: ConstitutionalScope | "none";
}

export interface GovernanceConflict {
  ruleIds: string[];
  reason: string;
}

export interface ConstitutionalRevocation {
  ruleId: string;
  revokedAt: string;
  reason: string;
  authority: string;
  provenance: string;
}
