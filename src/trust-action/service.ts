import { evaluateGovernedPipeline } from "./pipeline.js";
import type {
  GovernancePipelineFailure,
  GovernancePipelineResult,
} from "./pipeline-types.js";
import type {
  TrustToActionRequest,
  TrustToActionResult,
} from "./types.js";

function mapFailure(
  failure: GovernancePipelineFailure,
): TrustToActionResult {
  const decision =
    failure.decision.decision === "CONTAIN"
      ? "DENY"
      : failure.decision.decision;

  return {
    decision,
    reason: failure.decision.reason,
    trust: failure.trust,
    governance: null,
    authorization: null,
    action: null,
    evidence: null,
    audit: null,
  };
}

/**
 * Public trust-to-action boundary.
 *
 * Consequential decisions are produced exclusively by the authoritative
 * 19-stage GIIA governance pipeline.
 *
 * This adapter does not independently evaluate or construct ALLOW.
 * Authorization is not execution.
 */
export function evaluateTrustToAction(
  input: TrustToActionRequest,
): TrustToActionResult {
  const evidenceAuditRegistry = input.evidenceAuditRegistry;

  const pipelineResult = evaluateGovernedPipeline({
    request: {
      id: input.authorizationRequest.id,
      subjectIdentityId: input.authorizationRequest.subjectIdentityId,
      action: input.authorizationRequest.action,
      resource: input.authorizationRequest.resource,
      requestedAt: input.authorizationRequest.requestedAt,
      provenance: "trust-action-adapter",
    },
    identity: input.identity,
    authority: input.authority,
    trustChain: input.trustChain,
    trustRegistry: input.trustRegistry,
    evidenceAuditRegistry,
    authorizationRequest: input.authorizationRequest,
    binding: input.binding,
    governanceRules: input.governanceRules,
    constitutionalRules: input.constitutionalRules,
    ...(input.jurisdiction !== undefined
      ? { jurisdiction: input.jurisdiction }
      : {}),
    action: input.action,
    evidence: input.evidence,
    audit: input.audit,
  });

  if (pipelineResult.outcome === "FAILURE") {
    return mapFailure(pipelineResult);
  }

  const successfulPipeline: GovernancePipelineResult = pipelineResult;

  const decision =
    successfulPipeline.decision.decision === "CONTAIN"
      ? "DENY"
      : successfulPipeline.decision.decision;

  return {
    decision,
    reason: successfulPipeline.decision.reason,
    trust: successfulPipeline.trust,
    governance: successfulPipeline.policy.governance,
    authorization: successfulPipeline.authorization,
    action: input.action,
    evidence: successfulPipeline.evidence,
    audit: successfulPipeline.audit,
  };
}
