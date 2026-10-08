import { sha256 } from "../core/security.js";
import { canonicalize } from "../core/canonical.js";
import { validateNonEmpty, validateTimestamp } from "../core/validation.js";
import { invariant } from "../core/errors.js";
import {
  type RecoveryDecision,
  type RecoveryReason,
  type RecoveryAction,
  type StateTransition,
  type SystemState,
} from "./types.js";

export function transitionPayload(
  transition: StateTransition,
): Omit<StateTransition, "transitionHash"> {
  const { transitionHash: _transitionHash, ...payload } = transition;
  return payload;
}

export function createTransitionHash(
  transition: Omit<StateTransition, "transitionHash">,
): string {
  return sha256(canonicalize(transition));
}

export function createStateTransition(
  input: Omit<StateTransition, "transitionHash">,
): StateTransition {
  validateNonEmpty(
    input.id,
    "RESILIENCE_TRANSITION_ID_EMPTY",
    "Transition id is required",
  );

  validateNonEmpty(
    input.authorityId,
    "RESILIENCE_AUTHORITY_EMPTY",
    "Transition authority is required",
  );

  validateNonEmpty(
    input.evidenceRef,
    "RESILIENCE_EVIDENCE_EMPTY",
    "Transition evidence reference is required",
  );

  validateTimestamp(
    input.occurredAt,
    "RESILIENCE_TIMESTAMP_INVALID",
    "Transition timestamp is invalid",
  );

  invariant(
    input.from !== input.to,
    "RESILIENCE_NOOP_TRANSITION",
    "State transition must change state",
  );

  return {
    ...input,
    transitionHash: createTransitionHash(input),
  };
}

export function verifyStateTransition(
  transition: StateTransition,
): boolean {
  return (
    createTransitionHash(transitionPayload(transition)) ===
    transition.transitionHash
  );
}

export function verifyTransitionChain(
  transitions: StateTransition[],
): boolean {
  let previousHash: string | undefined;

  for (const transition of transitions) {
    if (!verifyStateTransition(transition)) {
      return false;
    }

    if (transition.previousTransitionHash !== previousHash) {
      return false;
    }

    previousHash = transition.transitionHash;
  }

  return true;
}

export function decideRecoveryTransition(
  from: SystemState,
  to: SystemState,
  reason: RecoveryReason,
): RecoveryDecision {
  if (from === to) {
    return {
      allowed: false,
      from,
      to,
      reason: "NO_STATE_CHANGE",
      requiresVerification: false,
    };
  }

  if (to === "RECOVERY") {
    return {
      allowed: true,
      from,
      to,
      reason: "RECOVERY_ENTRY_ALLOWED",
      requiresVerification: false,
    };
  }

  if (from === "COMPROMISED") {
    return {
      allowed: false,
      from,
      to,
      reason: "COMPROMISED_STATE_MUST_ENTER_RECOVERY",
      requiresVerification: true,
    };
  }

  if (from === "RECOVERY" && to === "ONLINE") {
    return {
      allowed: false,
      from,
      to,
      reason: "FINAL_VERIFICATION_REQUIRED_BEFORE_ONLINE",
      requiresVerification: true,
    };
  }

  if (from === "ONLINE" && to === "DEGRADED") {
    return {
      allowed: true,
      from,
      to,
      reason: reason === "SERVICE_DEGRADATION"
        ? "SERVICE_DEGRADATION_ACCEPTED"
        : "DEGRADED_STATE_ALLOWED",
      requiresVerification: false,
    };
  }

  if (
    (from === "ONLINE" || from === "DEGRADED") &&
    to === "OFFLINE"
  ) {
    return {
      allowed: true,
      from,
      to,
      reason: "OFFLINE_CONTINUITY_ALLOWED",
      requiresVerification: false,
    };
  }

  if (from === "OFFLINE" && to === "DEGRADED") {
    return {
      allowed: true,
      from,
      to,
      reason: "RECONNECTION_REQUIRES_DEGRADED_RECONCILIATION",
      requiresVerification: true,
    };
  }

  if (from === "DEGRADED" && to === "ONLINE") {
    return {
      allowed: true,
      from,
      to,
      reason: "DEGRADED_RESTORATION_ALLOWED",
      requiresVerification: true,
    };
  }

  if (to === "COMPROMISED") {
    return {
      allowed: true,
      from,
      to,
      reason: "COMPROMISE_CONTAINMENT_REQUIRED",
      requiresVerification: true,
    };
  }

  return {
    allowed: false,
    from,
    to,
    reason: "UNDEFINED_RESILIENCE_TRANSITION",
    requiresVerification: true,
  };
}
