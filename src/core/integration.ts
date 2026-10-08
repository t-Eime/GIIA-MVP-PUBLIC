import type { Identity } from "../identity/types.js";
import type { Authority } from "../authority/types.js";
import type {
  AuthorizationRequest,
  AuthorizationResult,
} from "../authorization/types.js";
import { authorize } from "../authorization/service.js";
import type {
  GovernanceRequest,
  GovernanceResult,
  GovernanceRule,
} from "../governance/types.js";
import { evaluateGovernance } from "../governance/service.js";

export interface CoreDecision {
  governance: GovernanceResult;
  authorization: AuthorizationResult | null;
  finalDecision: "ALLOW" | "DENY" | "DEFER";

  /**
   * This is a lower-level stage result only.
   *
   * It is never an authoritative consequential decision.
   * Authoritative consequential decisions must pass through
   * the complete governed trust-to-action boundary.
   */
  authoritative: false;

  reason: string;
}

/**
 * Evaluates the lower-level governance and authorization stages.
 *
 * IMPORTANT:
 * This function does NOT establish consequential authority.
 * It does NOT verify the complete trust-to-action chain.
 * It does NOT execute an action.
 *
 * A returned ALLOW is therefore only a stage-level ALLOW.
 * Callers must not treat it as an authoritative consequential
 * decision.
 */
export function evaluateCoreRequest(
  identity: Identity,
  authority: Authority,
  authorizationRequest: AuthorizationRequest,
  governanceRules: GovernanceRule[],
): CoreDecision {
  const governanceRequest: GovernanceRequest = {
    id: authorizationRequest.id,
    subject: authorizationRequest.subjectIdentityId,
    action: authorizationRequest.action,
    resource: authorizationRequest.resource,
    requestedAt: authorizationRequest.requestedAt,
    satisfiedConditions: [],
  };

  const governance = evaluateGovernance(governanceRequest, governanceRules);

  if (governance.decision === "DENY") {
    return {
      governance,
      authorization: null,
      finalDecision: "DENY",
      authoritative: false,
      reason: governance.reason,
    };
  }

  if (governance.decision === "DEFER") {
    return {
      governance,
      authorization: null,
      finalDecision: "DEFER",
      authoritative: false,
      reason: governance.reason,
    };
  }

  const authorization = authorize(
    authorizationRequest,
    identity,
    authority,
  );

  return {
    governance,
    authorization,
    finalDecision: authorization.decision,
    authoritative: false,
    reason: authorization.reason,
  };
}
