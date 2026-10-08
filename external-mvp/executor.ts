import { canonicalize } from "../src/core/canonical.js";
import { createHash } from "node:crypto";
import {
  DurableExternalReplayStore,
  type ExternalReplayStore,
} from "./replay-store.js";
import {
  verifyExternalEnforcement,
  type ExternalEnforcementAuthorization,
  type GovernanceDecisionReference,
} from "../src/enforcement/external-boundary.js";
import type { AgentPassport } from "../src/identity/agent-passport.js";

export interface ExternalExecutionEvidence {
  readonly evidenceId: string;
  readonly decisionId: string;
  readonly authorizationId: string;
  readonly executorId: string;
  readonly action: string;
  readonly target: string;
  readonly payloadHash: string;
  readonly executedAt: string;
  readonly outcome: "SUCCESS" | "FAILURE";
  readonly verificationReason: string;
  readonly evidenceHash: string;
}

export interface ExternalExecutionResult {
  readonly executed: boolean;
  readonly reason: string;
  readonly evidence: ExternalExecutionEvidence | null;
}

export interface ExternalExecutionEvidenceVerification {
  readonly valid: boolean;
  readonly reason: string;
}

export function verifyExternalExecutionEvidence(
  evidence: ExternalExecutionEvidence,
): ExternalExecutionEvidenceVerification {
  if (
    !evidence.evidenceId ||
    !evidence.decisionId ||
    !evidence.authorizationId ||
    !evidence.executorId ||
    !evidence.action ||
    !evidence.target ||
    !evidence.payloadHash ||
    !evidence.executedAt ||
    !evidence.verificationReason ||
    !evidence.evidenceHash
  ) {
    return {
      valid: false,
      reason: "EXECUTION_EVIDENCE_REQUIRED_FIELDS_MISSING",
    };
  }

  if (
    evidence.outcome !== "SUCCESS" &&
    evidence.outcome !== "FAILURE"
  ) {
    return {
      valid: false,
      reason: "EXECUTION_EVIDENCE_OUTCOME_INVALID",
    };
  }

  const { evidenceHash: _evidenceHash, ...unsignedEvidence } = evidence;

  const expectedHash = sha256(
    canonicalize(unsignedEvidence),
  );

  if (expectedHash !== evidence.evidenceHash) {
    return {
      valid: false,
      reason: "EXECUTION_EVIDENCE_HASH_MISMATCH",
    };
  }

  return {
    valid: true,
    reason: "EXECUTION_EVIDENCE_VERIFIED",
  };
}



function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Independent executor.
 *
 * This module is deliberately outside src/.
 * GIIA verifies authorization; this component performs the external action.
 */
const DEFAULT_REPLAY_STORE = new DurableExternalReplayStore(
  process.env.GIIA_EXTERNAL_REPLAY_PATH ??
    "runtime-data/external-mvp-replay.json",
);

export function executeExternally(input: {
  decision: GovernanceDecisionReference;
  authorization: ExternalEnforcementAuthorization;
  passport: AgentPassport;
  payload: unknown;
  capability: string;
  at: string;
  replayStore?: ExternalReplayStore;
}): ExternalExecutionResult {
  const verification = verifyExternalEnforcement(
    input.decision,
    input.authorization,
    input.passport,
    input.payload,
    input.capability,
    input.at,
  );

  if (verification.decision !== "PERMITTED") {
    return {
      executed: false,
      reason: verification.reason,
      evidence: null,
    };
  }

  const replayStore =
    input.replayStore ?? DEFAULT_REPLAY_STORE;

  /*
   * Replay is consumed only after every authorization, passport,
   * payload, expiry, approval, shutdown and signature check passes.
   *
   * consume() is one atomic store operation. This closes the
   * has()->record() race where two independent executor processes
   * could otherwise both observe an unused authorization.
   *
   * A blocked request therefore cannot burn a valid authorization.
   */
  if (!replayStore.consume(input.authorization.authorizationId)) {
    return {
      executed: false,
      reason: "EXTERNAL_AUTHORIZATION_REPLAYED",
      evidence: null,
    };
  }

  const payloadHash = sha256(canonicalize(input.payload));

  const unsignedEvidence = {
    evidenceId: `execution-${input.authorization.authorizationId}`,
    decisionId: input.decision.decisionId,
    authorizationId: input.authorization.authorizationId,
    executorId: input.authorization.executorId,
    action: input.decision.action,
    target: input.decision.target,
    payloadHash,
    executedAt: input.at,
    outcome: "SUCCESS" as const,
    verificationReason: verification.reason,
  };

  return {
    executed: true,
    reason: "EXTERNAL_ACTION_EXECUTED",
    evidence: {
      ...unsignedEvidence,
      evidenceHash: sha256(canonicalize(unsignedEvidence)),
    },
  };
}
