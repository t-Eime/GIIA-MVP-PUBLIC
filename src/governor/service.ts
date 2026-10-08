import type { GovernorAssessment, GovernorInput } from "./types.js";

export function evaluateGovernor(input: GovernorInput): GovernorAssessment {
  const base = {
    organ: "GOVERNOR" as const,
    requestId: input.requestId,
    actorId: input.actorId,
    action: input.action,
    target: input.target,
    issuedAt: input.at,
    authoritative: false as const,
    source: "ORGAN_ASSESSMENT" as const,
  };

  if (!input.authorityValid) {
    return { ...base, decision: "DENY", reason: "GOVERNOR_AUTHORITY_INVALID" };
  }

  if (!input.delegationValid) {
    return { ...base, decision: "DENY", reason: "GOVERNOR_DELEGATION_INVALID" };
  }

  if (!input.jurisdictionValid) {
    return { ...base, decision: "DENY", reason: "GOVERNOR_JURISDICTION_INVALID" };
  }

  if (!input.policyAllows) {
    return { ...base, decision: "DENY", reason: "GOVERNOR_POLICY_DENIED" };
  }

  if (!input.constitutionAllows) {
    return { ...base, decision: "DENY", reason: "GOVERNOR_CONSTITUTION_DENIED" };
  }

  if (input.prohibited) {
    return { ...base, decision: "DENY", reason: "GOVERNOR_PROHIBITED_ACTION" };
  }

  if (!input.evidenceValid) {
    return { ...base, decision: "DEFER", reason: "GOVERNOR_EVIDENCE_INSUFFICIENT" };
  }

  return { ...base, decision: "ALLOW", reason: "GOVERNOR_ALLOWED" };
}
