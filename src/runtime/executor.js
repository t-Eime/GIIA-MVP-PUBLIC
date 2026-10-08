/**
 * GIIA External Enforcement Boundary
 *
 * GIIA is a governance authority, not an execution authority.
 *
 * An ALLOW decision means only that the governed action satisfied
 * GIIA authorization requirements. It does not execute the action.
 *
 * Actual execution belongs to an independently governed external
 * enforcement system.
 */

export const REGISTERED_ACTIONS = Object.freeze([]);

export function requestExternalEnforcement() {
  throw new Error(
    "GIIA_ENFORCEMENT_BOUNDARY_FAIL_CLOSED: EXTERNAL_EXECUTOR_REQUIRED",
  );
}

export function verifyExternalExecutionEvidence() {
  return Object.freeze({
    valid: false,
    records: 0,
    head: null,
    reason: "EXTERNAL_EXECUTION_EVIDENCE_REQUIRED",
  });
}
