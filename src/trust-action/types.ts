import type { EvidenceAuditRegistry } from "../evidence-audit/registry.js";
import type { Identity } from "../identity/types.js";
import type { Authority } from "../authority/types.js";
import type { AuthorizationRequest, AuthorizationResult } from "../authorization/types.js";
import type { GovernanceRule, GovernanceResult } from "../governance/types.js";
import type { ConstitutionalRule } from "../constitution/types.js";
import type { TrustChainInput } from "../trust/service.js";
import type { TrustVerificationResult } from "../trust/types.js";
import type { Evidence } from "../evidence/types.js";
import type { AuditEvent } from "../audit/types.js";
import type { TrustRegistry } from "../trust/registry.js";

export interface TrustAuthorityBinding {
  credentialId: string;
  authorityId: string;
}

export interface ActionIntent {
  id: string;
  authorizationRequestId: string;
  actor: string;
  action: string;
  resource: string;
  provenance: string;
}

export interface ActionRecord extends ActionIntent {
  executedAt: string;
  outcome: "SUCCESS" | "FAILURE";
}

export interface TrustToActionRequest {
  identity: Identity;
  authority: Authority;
  trustChain: TrustChainInput;
  trustRegistry: TrustRegistry;
  binding: TrustAuthorityBinding;
  authorizationRequest: AuthorizationRequest;
  governanceRules: GovernanceRule[];
  constitutionalRules: ConstitutionalRule[];
  jurisdiction?: string;
  action: ActionIntent;
  evidence: Evidence;
  audit: AuditEvent;
  evidenceAuditRegistry: EvidenceAuditRegistry;
}

export interface TrustToActionResult {
  decision: "ALLOW" | "DENY" | "DEFER";
  reason: string;
  trust: TrustVerificationResult;
  governance: GovernanceResult | null;
  authorization: AuthorizationResult | null;
  action: ActionIntent | null;
  evidence: Evidence | null;
  audit: AuditEvent | null;
}
