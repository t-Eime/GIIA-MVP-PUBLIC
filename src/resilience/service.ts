import { validateTimestamp } from "../core/validation.js";
import {
  evaluateGovernedPipeline,
} from "../trust-action/pipeline.js";
import type {
  PipelineInput,
  GovernancePipelineResult,
} from "../trust-action/pipeline-types.js";
import type {
  ActionIntent,
  ActionRecord,
} from "../trust-action/types.js";
import {
  createStateTransition,
  decideRecoveryTransition,
} from "./state.js";
import {
  authorizeResilienceTransition,
  type ResilienceAuthorizationReceipt,
  type ResilienceTransitionIntent,
} from "./authorization.js";
import { ResilienceRegistry } from "./registry.js";
import type {
  RecoveryAction,
  RecoveryReason,
  StateTransition,
  SystemState,
} from "./types.js";
import {
  verifyAuthenticatedVerifier,
  type AuthenticatedVerifier,
} from "../trust/verifier.js";

function isActionRecord(action: ActionIntent): action is ActionRecord {
  return (
    typeof (action as Partial<ActionRecord>).executedAt === "string" &&
    ((action as Partial<ActionRecord>).outcome === "SUCCESS" ||
      (action as Partial<ActionRecord>).outcome === "FAILURE")
  );
}

export class ResilienceService {
  constructor(
    private readonly registry: ResilienceRegistry,
  ) {}

  currentState(): SystemState {
    return this.registry.getAuthoritativeState();
  }

  authorizeAndTransition(
    pipelineInput: PipelineInput,
    to: SystemState,
    reason: RecoveryReason,
    action: RecoveryAction,
    occurredAt: string,
    evidenceRef: string,
    verification?: {
      id: string;
      verifier: AuthenticatedVerifier;
    },
  ): StateTransition {
    validateTimestamp(
      occurredAt,
      "RESILIENCE_TIMESTAMP_INVALID",
      "Transition timestamp is invalid",
    );

    const from = this.currentState();

    const stateDecision =
      decideRecoveryTransition(
        from,
        to,
        reason,
      );

    if (!stateDecision.allowed) {
      throw new Error(
        `RESILIENCE_TRANSITION_DENIED:${stateDecision.reason}`,
      );
    }

    if (
      stateDecision.requiresVerification &&
      verification === undefined
    ) {
      throw new Error(
        "RESILIENCE_VERIFICATION_REQUIRED",
      );
    }

    if (verification !== undefined) {
      if (
        verification.id !== verification.verifier.verifierId ||
        !verifyAuthenticatedVerifier(
          verification.verifier,
          occurredAt,
        )
      ) {
        throw new Error(
          "RESILIENCE_VERIFIER_AUTHENTICATION_INVALID",
        );
      }
    }

    if (!isActionRecord(pipelineInput.action)) {
      throw new Error(
        "RESILIENCE_ACTION_RECORD_REQUIRED",
      );
    }

    const transitionId = pipelineInput.action.id;

    /*
     * The resilience action itself is authorized only by
     * the authoritative 19-stage GIIA pipeline.
     *
     * No caller-supplied ALLOW is accepted.
     */
    const pipelineResult =
      evaluateGovernedPipeline(
        pipelineInput,
      );

    if (
      pipelineResult.outcome !== "SUCCESS"
    ) {
      throw new Error(
        `RESILIENCE_PIPELINE_DENIED:${pipelineResult.decision.reason}`,
      );
    }

    if (
      pipelineResult.decision.decision !==
        "ALLOW" ||
      pipelineResult.decision.authoritative !==
        true
    ) {
      throw new Error(
        "RESILIENCE_PIPELINE_ALLOW_REQUIRED",
      );
    }

    if (verification !== undefined) {
      if (
        verification.verifier.identity.id === pipelineInput.identity.id ||
        verification.verifier.authority.id === pipelineResult.authority.id
      ) {
        throw new Error(
          "RESILIENCE_VERIFIER_NOT_INDEPENDENT",
        );
      }
    }

    if (
      pipelineInput.action.action !== action ||
      pipelineInput.action.executedAt !== occurredAt ||
      pipelineResult.evidence.id !== evidenceRef ||
      pipelineInput.request.action !== pipelineInput.action.action ||
      pipelineInput.request.resource !== pipelineInput.action.resource ||
      pipelineInput.request.subjectIdentityId !== pipelineInput.identity.id ||
      pipelineInput.authorizationRequest.subjectIdentityId !== pipelineInput.identity.id ||
      pipelineInput.authorizationRequest.authorityId !== pipelineResult.authority.id ||
      pipelineInput.authorizationRequest.action !== pipelineInput.action.action ||
      pipelineInput.authorizationRequest.resource !== pipelineInput.action.resource ||
      pipelineInput.authorizationRequest.requestedAt !== occurredAt ||
      pipelineInput.action.authorizationRequestId !== pipelineInput.request.id ||
      pipelineInput.action.actor !== pipelineInput.identity.id ||
      pipelineInput.action.outcome !== "SUCCESS"
    ) {
      throw new Error(
        "RESILIENCE_PIPELINE_INTENT_MISMATCH",
      );
    }

    const intent: ResilienceTransitionIntent = {
      transitionId,
      from,
      to,
      reason,
      action,
      occurredAt,
      evidenceRef,
    };

    const authorizationReceipt =
      authorizeResilienceTransition(
        pipelineResult,
        intent,
        pipelineInput.trustChain,
        pipelineInput.action,
        pipelineInput.authorizationRequest,
      );

    const previous =
      this.registry
        .listTransitions()
        .at(-1);

    const transition =
      createStateTransition({
        id: transitionId,
        from,
        to,
        reason,
        action,
        occurredAt,
        authorityId:
          pipelineResult.authority.id,
        evidenceRef,
        authorizationReceiptHash:
          authorizationReceipt.receiptHash,
        ...(previous === undefined
          ? {}
          : {
              previousTransitionHash:
                previous.transitionHash,
            }),
      });

    this.registry.authorizeTransitionCommit(
      transition,
      authorizationReceipt,
    );

    return transition;
  }

  /*
   * Deliberately retained as a fail-closed compatibility
   * boundary. The old Authority-only API cannot authorize
   * or commit a transition.
   */
  transition(): never {
    throw new Error(
      "RESILIENCE_AUTHORIZATION_REQUIRED: use authorizeAndTransition() with the authoritative GIIA pipeline",
    );
  }
}
