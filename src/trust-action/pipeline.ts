import {
  evaluateConstitution,
  isConstitutionalRuleAuthorized,
} from "../constitution/service.js";
import {
  evaluateGovernance,
  isGovernanceRuleApplicable,
  isGovernanceRuleAuthorized,
} from "../governance/service.js";
import { authorize } from "../authorization/service.js";
import {
  assessHarmRisk,
  classifyAction,
} from "../action-governance/index.js";
import { verifyTrustChain } from "../trust/service.js";
import { verifyEvidenceIntegrity } from "../evidence/service.js";
import { verifyAuditIntegrity } from "../audit/service.js";
import { constitutionalGate } from "./constitutional-gate.js";
import type {
  GovernancePipelineResult,
  PipelineInput,
  RequestStage,
  NormalizationStage,
  JurisdictionStage,
  PolicyStage,
  ActionClassStage,
  TargetStage,
  HarmRiskStage,
  ProhibitionStage,
  AssuranceStage,
  PipelineDecision,
  FinalGovernedDecision,
  EnforcementStage,
  GovernancePipelineStage,
  GovernancePipelineFailure,
  DelegationStage,
  DecisionStage,
  EvidenceStage,
  AuditCommitStage,
} from "./pipeline-types.js";

const PROVENANCE = "giia-authoritative-pipeline";

function deny(
  request: RequestStage,
  trust: GovernancePipelineResult["trust"],
  stages: readonly GovernancePipelineStage[],
  reason: string,
  decision: PipelineDecision["decision"] = "DENY",
): GovernancePipelineFailure {
  return {
    outcome: "FAILURE",
    decision: {
      requestId: request.id,
      decision,
      reason,
      authoritative: false,
      provenance: "giia-pipeline-failure",
    },
    stages,
    trust,
  };
}

export function evaluateGovernedPipeline(
  input: PipelineInput,
): GovernancePipelineResult | GovernancePipelineFailure {
  const request = input.request;
  const stages: GovernancePipelineStage[] = ["REQUEST"];

  if (
    request.id !== input.authorizationRequest.id ||
    request.subjectIdentityId !== input.authorizationRequest.subjectIdentityId ||
    request.action !== input.authorizationRequest.action ||
    request.resource !== input.authorizationRequest.resource ||
    request.requestedAt !== input.authorizationRequest.requestedAt
  ) {
    return deny(
      request,
      { valid: false, reason: "REQUEST_AUTHORIZATION_BINDING_INVALID" } as GovernancePipelineResult["trust"],
      stages,
      "REQUEST_AUTHORIZATION_BINDING_INVALID",
    );
  }

  const normalization: NormalizationStage = {
    requestId: request.id,
    subjectIdentityId: request.subjectIdentityId,
    action: request.action,
    resource: request.resource,
    requestedAt: request.requestedAt,
    normalized: true,
    provenance: request.provenance,
  };
  stages.push("NORMALIZATION");

  if (input.identity.id !== normalization.subjectIdentityId) {
    stages.push("IDENTITY");
    return deny(
      request,
      {
        valid: false,
        reason: "SUBJECT_IDENTITY_MISMATCH",
        chain: [],
      },
      stages,
      "SUBJECT_IDENTITY_MISMATCH",
    );
  }
  stages.push("IDENTITY");

  stages.push("CREDENTIAL");

  const trust = verifyTrustChain(input.trustChain);
  if (!trust.valid) {
    stages.push("TRUST");
    return deny(
      request,
      trust,
      stages,
      `TRUST_${trust.reason}`,
    );
  }
  stages.push("TRUST");

  const revokedObjects: Array<
    ["root" | "key" | "anchor" | "delegation" | "credential", string]
  > = [
    ["root", input.trustChain.root.id],
    ["key", input.trustChain.rootKey.id],
    ["anchor", input.trustChain.anchor.id],
    ["key", input.trustChain.anchorKey.id],
    ["delegation", input.trustChain.delegation.id],
    ["key", input.trustChain.delegationKey.id],
    ["credential", input.trustChain.credential.id],
  ];

  const revoked = revokedObjects.find(([type, id]) =>
    input.trustRegistry.isRevoked(type, id),
  );

  if (revoked) {
    return deny(
      request,
      trust,
      stages,
      `TRUST_REVOKED:${revoked[0]}:${revoked[1]}`,
    );
  }

  if (
    input.authority.trustCredentialId !== input.trustChain.credential.id
  ) {
    stages.push("AUTHORITY");
    return deny(
      request,
      trust,
      stages,
      "AUTHORITY_TRUST_CREDENTIAL_MISMATCH",
    );
  }

  if (
    input.trustChain.credential.claims.authorityId !==
    input.authority.id
  ) {
    stages.push("AUTHORITY");
    return deny(
      request,
      trust,
      stages,
      "CREDENTIAL_DOES_NOT_ASSERT_AUTHORITY",
    );
  }

  stages.push("AUTHORITY");

  if (
    input.binding.credentialId !== input.trustChain.credential.id ||
    input.binding.authorityId !== input.authority.id
  ) {
    stages.push("DELEGATION");
    return deny(
      request,
      trust,
      stages,
      "TRUST_AUTHORITY_BINDING_INVALID",
    );
  }

  if (
    input.trustChain.credential.subject !==
    input.authority.holderIdentityId
  ) {
    stages.push("DELEGATION");
    return deny(
      request,
      trust,
      stages,
      "CREDENTIAL_AUTHORITY_SUBJECT_MISMATCH",
    );
  }

  const delegation: DelegationStage = {
    requestId: request.id,
    delegationId: input.trustChain.delegation.id,
    credentialId: input.trustChain.credential.id,
    authorityId: input.authority.id,
    delegateeIdentityId: input.authority.holderIdentityId,
    verified: true,
    provenance: PROVENANCE,
  };
  stages.push("DELEGATION");

  const authorization = authorize(
    input.authorizationRequest,
    input.identity,
    input.authority,
  );
  stages.push("AUTHORIZATION");

  if (authorization.decision !== "ALLOW") {
    return deny(
      request,
      trust,
      stages,
      authorization.reason,
    );
  }

  const jurisdiction: JurisdictionStage = {
    requestId: request.id,
    ...(input.jurisdiction !== undefined
      ? { jurisdiction: input.jurisdiction }
      : {}),
    source: input.jurisdiction
      ? "governed-context"
      : "explicitly-none",
    provenance: "governed-input",
  };
  stages.push("JURISDICTION");

  const classifiedAction = classifyAction(request.action);
  if (
    !classifiedAction.determined ||
    classifiedAction.classification === null
  ) {
    return deny(
      request,
      trust,
      stages,
      classifiedAction.reason,
      "DEFER",
    );
  }

  const actionClass: ActionClassStage = {
    requestId: request.id,
    action: request.action,
    classification: classifiedAction.classification,
    provenance: classifiedAction.provenance,
  };
  stages.push("ACTION_CLASS");

  const target: TargetStage = {
    requestId: request.id,
    resource: request.resource,
    targetType: "resource",
    provenance: PROVENANCE,
  };
  stages.push("TARGET");

  const evaluatedHarmRisk = assessHarmRisk(
    request.action,
    request.resource,
    classifiedAction.classification,
  );

  const harmRisk: HarmRiskStage = {
    requestId: request.id,
    classification: evaluatedHarmRisk.classification,
    assessed: evaluatedHarmRisk.assessed,
    basis: evaluatedHarmRisk.basis,
    provenance: evaluatedHarmRisk.provenance,
  };
  stages.push("HARM_RISK");

  if (!harmRisk.assessed) {
    return deny(
      request,
      trust,
      stages,
      "HARM_RISK_UNASSESSED",
      "DEFER",
    );
  }

  const verifiedConstitutionalRuleIds = new Set<string>();

  for (const rule of input.constitutionalRules) {
    if (
      isConstitutionalRuleAuthorized(rule, {
        root: input.trustChain.root,
        rootKey: input.trustChain.rootKey,
        anchor: input.trustChain.anchor,
        anchorKey: input.trustChain.anchorKey,
        delegation: input.trustChain.delegation,
        delegationKey: input.trustChain.delegationKey,
        credential: input.trustChain.credential,
        at: input.trustChain.at,
      })
    ) {
      verifiedConstitutionalRuleIds.add(rule.id);
    }
  }

  const verifiedGovernanceRuleIds = new Set<string>();

  for (const rule of input.governanceRules) {
    if (
      isGovernanceRuleAuthorized(rule, {
        root: input.trustChain.root,
        rootKey: input.trustChain.rootKey,
        anchor: input.trustChain.anchor,
        anchorKey: input.trustChain.anchorKey,
        delegation: input.trustChain.delegation,
        delegationKey: input.trustChain.delegationKey,
        credential: input.trustChain.credential,
        at: input.trustChain.at,
      })
    ) {
      verifiedGovernanceRuleIds.add(rule.id);
    }
  }

  const governanceRequest = {
  id: request.id,
  subject: request.subjectIdentityId,
  action: request.action,
  resource: request.resource,
  requestedAt: request.requestedAt,
  ...(input.jurisdiction !== undefined
    ? { jurisdiction: input.jurisdiction }
    : {}),
  satisfiedConditions: [],
};

const applicableGovernanceRules = input.governanceRules.filter((rule) =>
  isGovernanceRuleApplicable(rule, governanceRequest),
);

  if (
    applicableGovernanceRules.some(
      (rule) => !verifiedGovernanceRuleIds.has(rule.id),
    )
  ) {
    return deny(
      request,
      trust,
      [...stages, "POLICY"],
      "UNVERIFIED_GOVERNANCE_RULE",
      "DEFER",
    );
  }

  const verifiedGovernanceRules = input.governanceRules.filter(
    (rule) => verifiedGovernanceRuleIds.has(rule.id),
  );

  const governance = evaluateGovernance(
  governanceRequest,
  verifiedGovernanceRules,
);

  const constitution =
    input.constitutionalRules.length > 0
      ? evaluateConstitution(
          {
            id: request.id,
            subject: request.subjectIdentityId,
            action: request.action,
            resource: request.resource,
            requestedAt: request.requestedAt,
            ...(input.jurisdiction !== undefined
              ? { jurisdiction: input.jurisdiction }
              : {}),
            satisfiedConditions: [],
          },
          input.constitutionalRules,
          verifiedConstitutionalRuleIds,
        )
      : null;

  const policy: PolicyStage = {
    requestId: request.id,
    governanceRules: input.governanceRules,
    constitutionalRules: input.constitutionalRules,
    governance,
    constitution,
    verifiedConstitutionalRuleIds: [...verifiedConstitutionalRuleIds],
    verifiedGovernanceRuleIds: [...verifiedGovernanceRuleIds],
    provenance: PROVENANCE,
  };
  stages.push("POLICY");

  const prohibition: ProhibitionStage = {
    requestId: request.id,
    prohibited:
      governance.decision === "DENY" ||
      constitution?.decision === "DENY",
    ruleIds: [
      ...governance.ruleIds,
      ...(constitution?.ruleIds ?? []),
    ],
    provenance: "governance-and-constitutional-evaluation",
  };
  stages.push("PROHIBITION");

  if (governance.decision !== "ALLOW") {
    return deny(
      request,
      trust,
      stages,
      governance.reason,
      governance.decision,
    );
  }

  if (constitution && constitution.decision !== "ALLOW") {
    return deny(
      request,
      trust,
      stages,
      constitution.reason,
      constitution.decision,
    );
  }

  const policyVerified =
    governance.decision === "ALLOW" &&
    (constitution === null || constitution.decision === "ALLOW");

  const assurance: AssuranceStage = {
    requestId: request.id,
    trustVerified: true,
    authorityVerified: true,
    authorizationVerified: true,
    policyVerified,
    evidenceRequired: true,
    auditRequired: true,
    satisfied: policyVerified,
    provenance: PROVENANCE,
  };
  stages.push("ASSURANCE");

  if (!assurance.satisfied) {
    return deny(
      request,
      trust,
      stages,
      "ASSURANCE_NOT_SATISFIED",
      "DEFER",
    );
  }

  if (
    input.action.authorizationRequestId !== request.id ||
    input.action.actor !== input.identity.id ||
    input.action.action !== request.action ||
    input.action.resource !== request.resource
  ) {
    return deny(
      request,
      trust,
      stages,
      "ACTION_AUTHORIZATION_BINDING_INVALID",
    );
  }

  const constitutionalGateResult = constitutionalGate(
    {
      authority: input.authority,
      credential: input.trustChain.credential,
      action: input.action,
      trust,
      authorization,
      constitution,
    },
    input.trustChain.at,
  );

  if (!constitutionalGateResult.allowed) {
    return deny(
      request,
      trust,
      [...stages, "DECISION"],
      constitutionalGateResult.reason,
    );
  }

  const decision: FinalGovernedDecision = {
    requestId: request.id,
    decision: "ALLOW",
    reason: constitutionalGateResult.reason,
    authoritative: true,
    provenance: PROVENANCE,
  };

  const decisionStage: DecisionStage = {
    requestId: request.id,
    decision: decision.decision,
    reason: decision.reason,
    authoritative: true,
    provenance: PROVENANCE,
  };
  stages.push("DECISION");

  const enforcement: EnforcementStage = {
    requestId: request.id,
    decision: "ALLOW",
    scope: input.authority.scope,
    executionPermitted: false,
    provenance: PROVENANCE,
  };
  stages.push("ENFORCEMENT");

  if (
    input.evidence.authorizationRequestId !== request.id ||
    input.evidence.action !== input.action.action ||
    input.evidence.subject !== input.identity.id ||
    !verifyEvidenceIntegrity(input.evidence)
  ) {
    return deny(
      request,
      trust,
      [...stages, "EVIDENCE"],
      "EVIDENCE_BINDING_OR_INTEGRITY_INVALID",
    );
  }

  const evidenceStage: EvidenceStage = {
    requestId: request.id,
    evidenceId: input.evidence.id,
    integrityVerified: true,
    committed: false,
    provenance: PROVENANCE,
  };
  stages.push("EVIDENCE");

  if (
    input.audit.authorizationRequestId !== request.id ||
    input.audit.evidenceId !== input.evidence.id ||
    input.audit.actor !== input.identity.id ||
    input.audit.action !== input.action.action ||
    input.audit.resource !== input.action.resource ||
    !verifyAuditIntegrity(input.audit)
  ) {
    return deny(
      request,
      trust,
      [...stages, "AUDIT_COMMIT"],
      "AUDIT_BINDING_OR_INTEGRITY_INVALID",
    );
  }

  stages.push("AUDIT_COMMIT");

  try {
    input.evidenceAuditRegistry.commitEvidenceAndAudit(
      input.evidence,
      input.audit,
    );
  } catch (error) {
    const reason =
      error instanceof Error
        ? `EVIDENCE_AUDIT_COMMIT_FAILED:${error.message}`
        : "EVIDENCE_AUDIT_COMMIT_FAILED";

    return deny(
      request,
      trust,
      stages,
      reason,
    );
  }

  const committedEvidenceStage: EvidenceStage = {
    ...evidenceStage,
    committed: true,
  };

  const auditCommitStage: AuditCommitStage = {
    requestId: request.id,
    auditId: input.audit.id,
    evidenceId: input.evidence.id,
    integrityVerified: true,
    committed: true,
    provenance: PROVENANCE,
  };

  return {
    outcome: "SUCCESS",
    decision,
    stages,
    request,
    normalization,
    identity: input.identity,
    credentialId: input.trustChain.credential.id,
    trust,
    authority: input.authority,
    delegation,
    jurisdiction,
    policy,
    verifiedGovernanceRuleIds: [...verifiedGovernanceRuleIds],
    actionClass,
    target,
    harmRisk,
    prohibition,
    assurance,
    authorization,
    decisionStage,
    enforcement,
    evidenceStage: committedEvidenceStage,
    auditCommitStage,
    evidence: input.evidence,
    audit: input.audit,
  };
}
