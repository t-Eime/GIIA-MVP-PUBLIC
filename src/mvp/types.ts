import type { TrustToActionResult } from "../trust-action/types.js";
import type { TrustChainInput } from "../trust/service.js";
import type { TrustCredential, TrustKey } from "../trust/types.js";
import type {
  SignedGovernanceKeyAuthorization,
} from "../governance-decision/authorization.js";
import type {
  GovernanceAuthorityCertificate,
  GovernanceAuthoritySet,
} from "../security/governance-authority.js";

export interface MvpEvaluateRequest {
  requestId: string;
  action: string;
  resource: string;
  requestedAt: string;
}

export interface MvpExecutionBinding {
  readonly actorId: string;
  readonly target: string;
  readonly payloadHash: string;
  readonly constitutionVersion: string;
  readonly nonce: string;
  readonly expiresAt: string;
}

export interface MvpDecisionRecord {
  version: "1";
  recordType: "GIIA_AUTHORITATIVE_DECISION";
  decisionId: string;
  requestId: string;
  action: string;
  resource: string;
  executionBinding: MvpExecutionBinding;
  decision: "ALLOW" | "DENY" | "DEFER";
  reason: string;
  authoritative: true;
  executionPermitted: false;
  provenance: string;
  issuedAt: string;

  signerKeyId: string;
  signerPublicKeyPem: string;
  signature: string;

  governanceAuthorization: SignedGovernanceKeyAuthorization;
  governanceAuthorizationFingerprint: string;
  governanceKey: TrustKey;
  governanceCredential: TrustCredential;
  governanceTrustChain: TrustChainInput;
  signingAuthorityId: string;

  governanceAuthoritySet: GovernanceAuthoritySet;
  governanceAuthorityCertificate: GovernanceAuthorityCertificate;
}

export interface MvpEvaluationResponse {
  decision: MvpDecisionRecord;
}

export interface MvpVerificationRequest {
  decision: MvpDecisionRecord;
}

export interface MvpVerificationResponse {
  valid: boolean;
  reason: string;
}

export interface MvpHealthResponse {
  service: "GIIA-MVP";
  status: "OK";
  version: "1";
  executionEndpoint: false;
}

export type MvpPipelineResult = TrustToActionResult;
