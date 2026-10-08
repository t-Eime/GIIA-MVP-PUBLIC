import { evaluateGovernor } from "../governor/service.js";
import { evaluateGuardian } from "../guardian/service.js";
import type { GovernorResult } from "../governor/types.js";
import type { GuardianResult } from "../guardian/types.js";
import type { GovernancePipelineResult } from "../trust-action/pipeline-types.js";
import type {
  IntegratedOrganAssessment,
  OrganPipelineProjection,
} from "./types.js";

function failClosedProjection(
  result: GovernancePipelineResult,
): OrganPipelineProjection {
  const pipeline = result.decision;

  return {
    requestId: result.request.id,
    actorId: result.identity.id,
    action: result.request.action,
    target: result.request.resource,

    pipelineDecision: pipeline.decision,
    pipelineProvenance: pipeline.provenance,

    authorityVerified: result.assurance.authorityVerified,
    delegationVerified: result.delegation.verified === true,
    jurisdictionVerified:
      result.jurisdiction.requestId === result.request.id &&
      (
        result.jurisdiction.source === "governed-context" ||
        result.jurisdiction.source === "explicitly-none"
      ),
    policyVerified: result.assurance.policyVerified,
    constitutionVerified:
      result.policy.constitution === null ||
      result.policy.constitution.decision === "ALLOW",
    prohibited: result.prohibition.prohibited,

    harmRisk: result.harmRisk.classification,
    harmRiskAssessed: result.harmRisk.assessed,

    evidenceIntegrityVerified: result.evidenceStage.integrityVerified,
    evidenceCommitted: result.evidenceStage.committed,
    auditIntegrityVerified: result.auditCommitStage.integrityVerified,
    auditCommitted: result.auditCommitStage.committed,

    assuranceSatisfied: result.assurance.satisfied,
    authorizationDecision: result.authorization.decision,

    exactActionBound:
      result.actionClass.requestId === result.request.id &&
      result.actionClass.action === result.request.action &&
      result.target.requestId === result.request.id &&
      result.target.resource === result.request.resource &&
      result.actionClass.requestId === result.target.requestId,

    executionPermitted: false,
  };
}

function governorFromProjection(
  projection: OrganPipelineProjection,
  at: string,
): GovernorResult {
  const pipelineAllows = projection.pipelineDecision === "ALLOW";

  const decision =
    !pipelineAllows
      ? "DENY"
      : !projection.authorityVerified
        ? "DENY"
        : !projection.delegationVerified
          ? "DENY"
          : !projection.jurisdictionVerified
            ? "DENY"
            : !projection.policyVerified
              ? "DENY"
              : !projection.constitutionVerified
                ? "DENY"
                : projection.prohibited
                  ? "DENY"
                  : !projection.evidenceIntegrityVerified ||
                      !projection.evidenceCommitted ||
                      !projection.auditIntegrityVerified ||
                      !projection.auditCommitted
                    ? "DEFER"
                    : "ALLOW";

  let reason: string;

  if (!pipelineAllows) {
    reason = `GOVERNOR_PIPELINE_${projection.pipelineDecision}`;
  } else if (!projection.authorityVerified) {
    reason = "GOVERNOR_PIPELINE_AUTHORITY_NOT_VERIFIED";
  } else if (!projection.delegationVerified) {
    reason = "GOVERNOR_PIPELINE_DELEGATION_NOT_VERIFIED";
  } else if (!projection.jurisdictionVerified) {
    reason = "GOVERNOR_PIPELINE_JURISDICTION_NOT_VERIFIED";
  } else if (!projection.policyVerified) {
    reason = "GOVERNOR_PIPELINE_POLICY_NOT_VERIFIED";
  } else if (!projection.constitutionVerified) {
    reason = "GOVERNOR_PIPELINE_CONSTITUTION_NOT_VERIFIED";
  } else if (projection.prohibited) {
    reason = "GOVERNOR_PIPELINE_PROHIBITED";
  } else if (
    !projection.evidenceIntegrityVerified ||
    !projection.evidenceCommitted ||
    !projection.auditIntegrityVerified ||
    !projection.auditCommitted
  ) {
    reason = "GOVERNOR_PIPELINE_EVIDENCE_AUDIT_NOT_COMMITTED";
  } else {
    reason = "GOVERNOR_PIPELINE_LEGITIMACY_VERIFIED";
  }

  return {
    organ: "GOVERNOR",
    decision,
    reason,
    requestId: projection.requestId,
    actorId: projection.actorId,
    action: projection.action,
    target: projection.target,
    issuedAt: at,
    authoritative: true,
    source: "AUTHORITATIVE_GIIA_PIPELINE",
  };
}

function guardianFromProjection(
  projection: OrganPipelineProjection,
  at: string,
): GuardianResult {
  const pipelineAllows = projection.pipelineDecision === "ALLOW";

  const integrityConditionsValid =
    projection.evidenceIntegrityVerified &&
    projection.evidenceCommitted &&
    projection.auditIntegrityVerified &&
    projection.auditCommitted &&
    projection.assuranceSatisfied &&
    projection.exactActionBound;

  /*
   * Guardian does not create a new harm policy.
   *
   * Harm classification is authoritative pipeline output.
   * The Guardian verifies that the pipeline reached an allowable
   * state and that the evidence/audit/action bindings remain intact.
   */
  const decision =
    !pipelineAllows
      ? "DENY"
      : !integrityConditionsValid
        ? "CONTAIN"
        : projection.prohibited
          ? "DENY"
          : "ALLOW";

  let reason: string;

  if (!pipelineAllows) {
    reason = `GUARDIAN_PIPELINE_${projection.pipelineDecision}`;
  } else if (!integrityConditionsValid) {
    reason = "GUARDIAN_PIPELINE_INTEGRITY_CONDITIONS_INVALID";
  } else if (projection.prohibited) {
    reason = "GUARDIAN_PIPELINE_PROHIBITED";
  } else {
    reason = "GUARDIAN_PIPELINE_SAFETY_BOUNDARY_VERIFIED";
  }

  return {
    organ: "GUARDIAN",
    decision,
    reason,
    requestId: projection.requestId,
    actorId: projection.actorId,
    action: projection.action,
    target: projection.target,
    issuedAt: at,
    authoritative: true,
    source: "AUTHORITATIVE_GIIA_PIPELINE",
  };
}

export function projectPipelineForOrgans(
  result: GovernancePipelineResult,
): OrganPipelineProjection {
  return failClosedProjection(result);
}

export function assessPipelineWithOrgans(
  result: GovernancePipelineResult,
  at: string,
): IntegratedOrganAssessment {
  const assessmentTime = Date.parse(at);

  if (!Number.isFinite(assessmentTime)) {
    throw new Error("ORGAN_ASSESSMENT_TIME_INVALID");
  }

  if (assessmentTime > Date.now()) {
    throw new Error("ORGAN_ASSESSMENT_TIME_IN_FUTURE");
  }

  const projection = projectPipelineForOrgans(result);

  const governor = governorFromProjection(projection, at);
  const guardian = guardianFromProjection(projection, at);

  return {
    governor,
    guardian,
    projection,
  };
}
