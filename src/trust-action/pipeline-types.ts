import type { Identity } from "../identity/types.js";
import type { Authority } from "../authority/types.js";
import type {
  AuthorizationRequest,
  AuthorizationResult,
} from "../authorization/types.js";
import type {
  GovernanceRule,
  GovernanceResult,
} from "../governance/types.js";
import type {
  ConstitutionalRule,
  ConstitutionalResult,
} from "../constitution/types.js";
import type { TrustChainInput } from "../trust/service.js";
import type { TrustVerificationResult } from "../trust/types.js";
import type { Evidence } from "../evidence/types.js";
import type { AuditEvent } from "../audit/types.js";
import type { TrustRegistry } from "../trust/registry.js";
import type { EvidenceAuditRegistry } from "../evidence-audit/registry.js";
import type { ActionIntent } from "./types.js";

export const GOVERNANCE_PIPELINE_STAGES = [
  "REQUEST",
  "NORMALIZATION",
  "IDENTITY",
  "CREDENTIAL",
  "TRUST",
  "AUTHORITY",
  "DELEGATION",
  "AUTHORIZATION",
  "JURISDICTION",
  "POLICY",
  "ACTION_CLASS",
  "TARGET",
  "HARM_RISK",
  "PROHIBITION",
  "ASSURANCE",
  "DECISION",
  "ENFORCEMENT",
  "EVIDENCE",
  "AUDIT_COMMIT",
] as const;

export type GovernancePipelineStage =
  (typeof GOVERNANCE_PIPELINE_STAGES)[number];

export interface RequestStage {
  id: string;
  subjectIdentityId: string;
  action: string;
  resource: string;
  requestedAt: string;
  provenance: string;
}

export interface NormalizationStage {
  requestId: string;
  subjectIdentityId: string;
  action: string;
  resource: string;
  requestedAt: string;
  normalized: true;
  provenance: string;
}

export interface DelegationStage {
  requestId: string;
  delegationId: string;
  credentialId: string;
  authorityId: string;
  delegateeIdentityId: string;
  verified: true;
  provenance: string;
}

export interface JurisdictionStage {
  requestId: string;
  jurisdiction?: string;
  source: "governed-context" | "explicitly-none";
  provenance: string;
}

export type ActionClass =
  | "READ"
  | "WRITE"
  | "EXECUTE"
  | "ADMINISTRATIVE"
  | "CONSEQUENTIAL";

export interface ActionClassStage {
  requestId: string;
  action: string;
  classification: ActionClass;
  provenance: string;
}

export interface TargetStage {
  requestId: string;
  resource: string;
  targetType: "resource";
  provenance: string;
}

export type HarmRiskLevel =
  | "LOW"
  | "MODERATE"
  | "HIGH"
  | "CRITICAL"
  | "UNKNOWN";

export interface HarmRiskStage {
  requestId: string;
  classification: HarmRiskLevel;
  assessed: boolean;
  basis: string;
  provenance: string;
}

export interface ProhibitionStage {
  requestId: string;
  prohibited: boolean;
  ruleIds: string[];
  provenance: string;
}

export interface PolicyStage {
  requestId: string;
  governanceRules: GovernanceRule[];
  verifiedGovernanceRuleIds: string[];
  constitutionalRules: ConstitutionalRule[];
  governance: GovernanceResult | null;
  constitution: ConstitutionalResult | null;
  verifiedConstitutionalRuleIds: string[];
  provenance: string;
}

export interface AssuranceStage {
  requestId: string;
  trustVerified: boolean;
  authorityVerified: boolean;
  authorizationVerified: boolean;
  policyVerified: boolean;
  evidenceRequired: boolean;
  auditRequired: boolean;
  satisfied: boolean;
  provenance: string;
}

export interface PipelineDecision {
  requestId: string;
  decision: "ALLOW" | "DENY" | "DEFER" | "CONTAIN";
  reason: string;
  authoritative: false;
  provenance: string;
}

export interface FinalGovernedDecision {
  requestId: string;
  decision: "ALLOW" | "DENY" | "DEFER" | "CONTAIN";
  reason: string;
  authoritative: true;
  provenance: string;
}

export interface DecisionStage {
  requestId: string;
  decision: FinalGovernedDecision["decision"];
  reason: string;
  authoritative: true;
  provenance: string;
}

export interface EnforcementStage {
  requestId: string;
  decision: PipelineDecision["decision"];
  scope: string[];
  executionPermitted: false;
  provenance: string;
}

export interface EvidenceStage {
  requestId: string;
  evidenceId: string;
  integrityVerified: boolean;
  committed: boolean;
  provenance: string;
}

export interface AuditCommitStage {
  requestId: string;
  auditId: string;
  evidenceId: string;
  integrityVerified: boolean;
  committed: boolean;
  provenance: string;
}

export interface GovernancePipelineFailure {
  outcome: "FAILURE";
  decision: PipelineDecision;
  stages: readonly GovernancePipelineStage[];
  trust: TrustVerificationResult;
}

export interface PipelineInput {
  request: RequestStage;
  identity: Identity;
  authority: Authority;
  trustChain: TrustChainInput;
  trustRegistry: TrustRegistry;
  evidenceAuditRegistry: EvidenceAuditRegistry;
  authorizationRequest: AuthorizationRequest;
  binding: {
    credentialId: string;
    authorityId: string;
  };
  governanceRules: GovernanceRule[];
  constitutionalRules: ConstitutionalRule[];
  jurisdiction?: string;
  action: ActionIntent;
  evidence: Evidence;
  audit: AuditEvent;
}

export interface GovernancePipelineResult {
  outcome: "SUCCESS";
  decision: FinalGovernedDecision;
  stages: readonly GovernancePipelineStage[];
  request: RequestStage;
  normalization: NormalizationStage;
  identity: Identity;
  credentialId: string;
  trust: TrustVerificationResult;
  authority: Authority;
  delegation: DelegationStage;
  jurisdiction: JurisdictionStage;
  policy: PolicyStage;
  verifiedGovernanceRuleIds: string[];
  actionClass: ActionClassStage;
  target: TargetStage;
  harmRisk: HarmRiskStage;
  prohibition: ProhibitionStage;
  assurance: AssuranceStage;
  authorization: AuthorizationResult;
  decisionStage: DecisionStage;
  enforcement: EnforcementStage;
  evidenceStage: EvidenceStage;
  auditCommitStage: AuditCommitStage;
  evidence: Evidence;
  audit: AuditEvent;
}
