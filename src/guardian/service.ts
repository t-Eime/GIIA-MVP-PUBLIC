import type { GuardianAssessment, GuardianInput } from "./types.js";

export function evaluateGuardian(input: GuardianInput): GuardianAssessment {
  const base = {
    organ: "GUARDIAN" as const,
    requestId: input.requestId,
    actorId: input.actorId,
    action: input.action,
    target: input.target,
    issuedAt: input.at,
    authoritative: false as const,
    source: "ORGAN_ASSESSMENT" as const,
  };

  if (!input.integrityConditionsValid) {
    return { ...base, decision: "CONTAIN", reason: "GUARDIAN_INTEGRITY_FAILURE" };
  }

  if (!input.harmAcceptable) {
    return { ...base, decision: "DENY", reason: "GUARDIAN_HARM_UNACCEPTABLE" };
  }

  if (!input.emergencyValid) {
    return { ...base, decision: "DENY", reason: "GUARDIAN_EMERGENCY_INVALID" };
  }

  if (!input.resourceConditionsValid) {
    return { ...base, decision: "DENY", reason: "GUARDIAN_RESOURCE_CONDITIONS_INVALID" };
  }

  if (!input.anomalyResolved) {
    return { ...base, decision: "DEFER", reason: "GUARDIAN_ANOMALY_UNRESOLVED" };
  }

  if (!input.evidenceValid) {
    return { ...base, decision: "DEFER", reason: "GUARDIAN_EVIDENCE_INSUFFICIENT" };
  }

  return { ...base, decision: "ALLOW", reason: "GUARDIAN_ALLOWED" };
}
