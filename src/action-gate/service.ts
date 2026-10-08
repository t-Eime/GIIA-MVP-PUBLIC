import type { ActionGateInput, ActionGateResult } from "./types.js";

function block(input: ActionGateInput, reason: string): ActionGateResult {
  return {
    decision: "BLOCK",
    reason,
    executable: false,
    governorDecision: input.governor.decision,
    guardianDecision: input.guardian.decision,
  };
}

/**
 * Final constitutional action gate.
 *
 * This gate produces permission for the independent enforcement boundary.
 * It never executes an action.
 */
export function evaluateActionGate(input: ActionGateInput): ActionGateResult {
  if (
    input.governor.authoritative !== true ||
    input.governor.source !== "AUTHORITATIVE_GIIA_PIPELINE"
  ) {
    return block(input, "GOVERNOR_NOT_AUTHORITATIVE_PIPELINE_RESULT");
  }

  if (
    input.guardian.authoritative !== true ||
    input.guardian.source !== "AUTHORITATIVE_GIIA_PIPELINE"
  ) {
    return block(input, "GUARDIAN_NOT_AUTHORITATIVE_PIPELINE_RESULT");
  }

  if (input.governor.decision !== "ALLOW") {
    return block(input, "GOVERNOR_NOT_ALLOW");
  }

  if (input.guardian.decision !== "ALLOW") {
    return block(input, "GUARDIAN_NOT_ALLOW");
  }

  if (!input.governorIntegrity.verified) {
    return block(input, "GOVERNOR_INSTITUTIONAL_INTEGRITY_NOT_VERIFIED");
  }

  if (!input.guardianIntegrity.verified) {
    return block(input, "GUARDIAN_INSTITUTIONAL_INTEGRITY_NOT_VERIFIED");
  }

  if (!input.evidenceValid) {
    return block(input, "EVIDENCE_INVALID");
  }

  if (!input.authorityValid) {
    return block(input, "AUTHORITY_INVALID");
  }

  if (!input.constitutionAllows) {
    return block(input, "CONSTITUTION_NOT_ALLOWED");
  }

  if (!input.conditionsValid) {
    return block(input, "MANDATORY_CONDITIONS_INVALID");
  }

  if (!input.noUnresolvedConflict) {
    return block(input, "UNRESOLVED_CONFLICT");
  }

  if (!input.enforcementHealthy) {
    return block(input, "ENFORCEMENT_BOUNDARY_UNHEALTHY");
  }

  if (!input.exactActionBound) {
    return block(input, "EXACT_ACTION_NOT_BOUND");
  }

  if (!input.actionNotAlreadyExecuted) {
    return block(input, "ACTION_ALREADY_EXECUTED");
  }

  if (!input.criticalTrustRootsHealthy) {
    return block(input, "CRITICAL_TRUST_ROOT_COMPROMISED");
  }

  return {
    decision: "ALLOW_EXECUTION",
    reason: "BOTH_ORGANS_AND_ALL_MANDATORY_CONTROLS_VERIFIED",
    executable: true,
    governorDecision: input.governor.decision,
    guardianDecision: input.guardian.decision,
  };
}
