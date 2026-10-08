import { canonicalHash } from "../core/canonical.js";
import { verifyTrustChain } from "../trust/service.js";
import type { Authority } from "../authority/types.js";
import type { TrustChainInput } from "../trust/service.js";
import type { ActionRecord } from "../trust-action/types.js";
import type {
  GovernancePipelineResult,
} from "../trust-action/pipeline-types.js";
import type { AuthorizationRequest } from "../authorization/types.js";
import type { Evidence } from "../evidence/types.js";
import { verifyEvidenceIntegrity } from "../evidence/service.js";
import type { AuditEvent } from "../audit/types.js";
import { verifyAuditIntegrity } from "../audit/service.js";
import type {
  RecoveryAction,
  RecoveryReason,
  SystemState,
} from "./types.js";

export interface ResilienceTransitionIntent {
  transitionId: string;
  from: SystemState;
  to: SystemState;
  reason: RecoveryReason;
  action: RecoveryAction;
  occurredAt: string;
  evidenceRef: string;
}

export interface ResilienceAuthorizationReceipt {
  id: string;
  intent: ResilienceTransitionIntent;
  requestId: string;
  decision: GovernancePipelineResult["decision"];
  identityId: string;
  authorizationRequest: AuthorizationRequest;
  authority: Authority;
  trustChain: TrustChainInput;
  action: ActionRecord;
  evidence: Evidence;
  audit: AuditEvent;
  verifiedGovernanceRuleIds: string[];
  receiptHash: string;
}

function unsignedReceipt(
  receipt: ResilienceAuthorizationReceipt,
): Omit<ResilienceAuthorizationReceipt, "receiptHash"> {
  const { receiptHash: _hash, ...payload } = receipt;
  return payload;
}

function createResilienceAuthorizationReceipt(
  result: GovernancePipelineResult,
  intent: ResilienceTransitionIntent,
  trustChain: TrustChainInput,
  action: ActionRecord,
  authorizationRequest: AuthorizationRequest,
): ResilienceAuthorizationReceipt {
  if (
    result.decision.decision !== "ALLOW" ||
    result.decision.authoritative !== true
  ) {
    throw new Error(
      "RESILIENCE_RECEIPT_AUTHORITATIVE_ALLOW_REQUIRED",
    );
  }

  if (!verifyTrustChain(trustChain).valid) {
    throw new Error(
      "RESILIENCE_RECEIPT_TRUST_CHAIN_INVALID",
    );
  }

  if (
    authorizationRequest.id !== result.request.id ||
    authorizationRequest.requestedAt !== result.request.requestedAt ||
    authorizationRequest.subjectIdentityId !== result.identity.id ||
    authorizationRequest.authorityId !== result.authority.id ||
    authorizationRequest.action !== action.action ||
    authorizationRequest.resource !== action.resource ||
    authorizationRequest.requestedAt !== intent.occurredAt ||
    action.authorizationRequestId !== authorizationRequest.id ||
    action.actor !== authorizationRequest.subjectIdentityId
  ) {
    throw new Error(
      "RESILIENCE_RECEIPT_AUTHORIZATION_REQUEST_BINDING_INVALID",
    );
  }

  if (
    action.action !== intent.action ||
    action.executedAt !== intent.occurredAt ||
    action.outcome !== "SUCCESS"
  ) {
    throw new Error(
      "RESILIENCE_RECEIPT_ACTION_BINDING_INVALID",
    );
  }

  if (result.evidence.id !== intent.evidenceRef) {
    throw new Error(
      "RESILIENCE_RECEIPT_EVIDENCE_BINDING_INVALID",
    );
  }

  const receiptWithoutHash: Omit<
    ResilienceAuthorizationReceipt,
    "receiptHash"
  > = {
    id: `resilience-receipt-${intent.transitionId}`,
    intent,
    requestId: result.decision.requestId,
    decision: result.decision,
    identityId: result.identity.id,
    authorizationRequest,
    authority: result.authority,
    trustChain,
    action,
    evidence: result.evidence,
    audit: result.audit,
    verifiedGovernanceRuleIds: [
      ...result.verifiedGovernanceRuleIds,
    ],
  };

  const receiptHash = canonicalHash(receiptWithoutHash);

  return {
    ...receiptWithoutHash,
    receiptHash,
  };
}


export function authorizeResilienceTransition(
  result: GovernancePipelineResult,
  intent: ResilienceTransitionIntent,
  trustChain: TrustChainInput,
  action: ActionRecord,
  authorizationRequest: AuthorizationRequest,
): ResilienceAuthorizationReceipt {
  return createResilienceAuthorizationReceipt(
    result,
    intent,
    trustChain,
    action,
    authorizationRequest,
  );
}

export function verifyResilienceAuthorizationReceipt(
  receipt: ResilienceAuthorizationReceipt,
): boolean {
  if (
    receipt.id !==
    `resilience-receipt-${receipt.intent.transitionId}`
  ) {
    return false;
  }

  if (
    receipt.decision.decision !== "ALLOW" ||
    receipt.decision.authoritative !== true
  ) {
    return false;
  }

  if (receipt.requestId !== receipt.decision.requestId) {
    return false;
  }

  if (receipt.identityId !== receipt.authorizationRequest.subjectIdentityId) {
    return false;
  }

  if (
    receipt.authorizationRequest.requestedAt !==
    receipt.intent.occurredAt
  ) {
    return false;
  }

  if (
    receipt.authorizationRequest.authorityId !==
    receipt.authority.id
  ) {
    return false;
  }

  if (receipt.authorizationRequest.action !== receipt.action.action) {
    return false;
  }

  if (receipt.authorizationRequest.resource !== receipt.action.resource) {
    return false;
  }

  if (receipt.action.id !== receipt.intent.transitionId) {
    return false;
  }

  if (receipt.action.executedAt !== receipt.intent.occurredAt) {
    return false;
  }

  if (receipt.action.action !== receipt.intent.action) {
    return false;
  }

  if (receipt.action.authorizationRequestId !== receipt.requestId) {
    return false;
  }

  if (receipt.action.actor !== receipt.identityId) {
    return false;
  }

  if (receipt.action.outcome !== "SUCCESS") {
    return false;
  }

  if (receipt.action.provenance.trim().length === 0) {
    return false;
  }

  if (receipt.evidence.id !== receipt.intent.evidenceRef) {
    return false;
  }

  if (receipt.evidence.authorizationRequestId !== receipt.requestId) {
    return false;
  }

  if (receipt.evidence.action !== receipt.action.action) {
    return false;
  }

  if (receipt.evidence.subject !== receipt.identityId) {
    return false;
  }

  if (receipt.evidence.occurredAt !== receipt.action.executedAt) {
    return false;
  }

  if (receipt.evidence.provenance.trim().length === 0) {
    return false;
  }

  if (!verifyEvidenceIntegrity(receipt.evidence)) {
    return false;
  }

  if (receipt.audit.authorizationRequestId !== receipt.requestId) {
    return false;
  }

  if (receipt.audit.evidenceId !== receipt.evidence.id) {
    return false;
  }

  if (receipt.audit.actor !== receipt.action.actor) {
    return false;
  }

  if (receipt.audit.action !== receipt.action.action) {
    return false;
  }

  if (receipt.audit.resource !== receipt.action.resource) {
    return false;
  }

  if (receipt.audit.outcome !== "EXECUTED") {
    return false;
  }

  if (receipt.audit.occurredAt !== receipt.action.executedAt) {
    return false;
  }

  if (receipt.audit.provenance.trim().length === 0) {
    return false;
  }

  if (!verifyAuditIntegrity(receipt.audit)) {
    return false;
  }

  if (receipt.authority.holderIdentityId !== receipt.action.actor) {
    return false;
  }

  if (
    receipt.authority.trustCredentialId !==
    receipt.trustChain.credential.id
  ) {
    return false;
  }

  if (
    receipt.trustChain.credential.claims.authorityId !==
    receipt.authority.id
  ) {
    return false;
  }

  const trustResult = verifyTrustChain(receipt.trustChain);

  if (!trustResult.valid) {
    return false;
  }

  if (receipt.verifiedGovernanceRuleIds.length === 0) {
    return false;
  }

  return (
    canonicalHash(unsignedReceipt(receipt)) ===
    receipt.receiptHash
  );
}
