import { createHash, randomUUID } from "node:crypto";

import { canonicalize } from "../core/canonical.js";
import { invariant } from "../core/errors.js";
import {
  signCanonical,
  verifyCanonical,
  generateEd25519KeyPair,
} from "../trust/crypto.js";
import {
  verifyGovernanceKeyAuthorization,
  governanceKeyAuthorizationFingerprint,
  type SignedGovernanceKeyAuthorization,
} from "./authorization.js";
import type { TrustChainInput } from "../trust/service.js";
import type { TrustCredential, TrustKey } from "../trust/types.js";
import type { KeySecurityBoundary } from "../security/key-boundary.js";
import type {
  GovernanceDecisionPayload,
  SignedGovernanceDecision,
  GovernanceDecisionVerificationResult,
} from "./types.js";

export interface GovernanceDecisionAuthorization {
  readonly authorization: SignedGovernanceKeyAuthorization;
  readonly credential: TrustCredential;
  readonly governanceKey: TrustKey;
  readonly trustChain: TrustChainInput;
  readonly signingAuthorityId: string;
}

export interface CreateGovernanceDecisionInput {
  readonly requestId: string;
  readonly actorId: string;
  readonly passportId: string;
  readonly action: string;
  readonly target: string;
  readonly payloadHash: string;
  readonly constitutionVersion: string;
  readonly governanceContext: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce?: string;
  readonly authorization: GovernanceDecisionAuthorization;
  readonly boundary: KeySecurityBoundary;
}

export interface VerifyGovernanceDecisionInput {
  readonly decision: SignedGovernanceDecision;
  readonly authorization: SignedGovernanceKeyAuthorization;
  readonly governanceKey: TrustKey;
  readonly credential: TrustCredential;
  readonly trustChain: TrustChainInput;
  readonly at: string;
}

function sha256Canonical(value: unknown): string {
  return createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex");
}

export function createGovernanceSigningKey(
  id: string,
  provenance: string,
  createdAt: string,
): { key: TrustKey; privateKeyPem: string } {
  const pair = generateEd25519KeyPair();

  const key: TrustKey = {
    id,
    algorithm: "Ed25519",
    purpose: "governance",
    publicKeyPem: pair.publicKeyPem,
    createdAt,
    notBefore: createdAt,
    status: "active",
    provenance,
  };

  return {
    key,
    privateKeyPem: pair.privateKeyPem,
  };
}

export function validateGovernanceDecisionAuthorization(
  authorization: GovernanceDecisionAuthorization,
): void {
  invariant(
    authorization.governanceKey.purpose === "governance",
    "GOVERNANCE_KEY_PURPOSE_INVALID",
    "Governance decision signing requires a dedicated governance key",
  );

  invariant(
    authorization.governanceKey.status === "active",
    "GOVERNANCE_KEY_NOT_ACTIVE",
    "Governance decision signing key is not active",
  );

  invariant(
    authorization.credential.subject === authorization.signingAuthorityId,
    "GOVERNANCE_SIGNING_AUTHORITY_MISMATCH",
    "Governance signing authority does not match credential subject",
  );

  invariant(
    authorization.authorization.payload.governanceKeyId ===
      authorization.governanceKey.id,
    "GOVERNANCE_AUTHORIZATION_KEY_MISMATCH",
    "Governance authorization is not bound to the supplied governance key",
  );

  invariant(
    authorization.authorization.payload.signingAuthorityId ===
      authorization.signingAuthorityId,
    "GOVERNANCE_AUTHORIZATION_AUTHORITY_MISMATCH",
    "Governance authorization is not bound to the signing authority",
  );

  invariant(
    authorization.authorization.payload.credentialId ===
      authorization.credential.id,
    "GOVERNANCE_AUTHORIZATION_CREDENTIAL_MISMATCH",
    "Governance authorization is not bound to the supplied credential",
  );
}

export function createSignedGovernanceDecision(
  input: CreateGovernanceDecisionInput,
): SignedGovernanceDecision {
  validateGovernanceDecisionAuthorization(input.authorization);

  const authorizationFingerprint =
    governanceKeyAuthorizationFingerprint(
      input.authorization.authorization,
    );

  invariant(
    verifyGovernanceKeyAuthorization({
      authorization: input.authorization.authorization,
      governanceKey: input.authorization.governanceKey,
      credential: input.authorization.credential,
      trustChain: input.authorization.trustChain,
      at: input.issuedAt,
    }),
    "GOVERNANCE_AUTHORIZATION_INVALID",
    "Governance key authorization is not valid at decision issuance",
  );

  const payload: GovernanceDecisionPayload = {
    decisionId: randomUUID(),
    requestId: input.requestId,
    decision: "ALLOW",
    actorId: input.actorId,
    passportId: input.passportId,
    action: input.action,
    target: input.target,
    payloadHash: input.payloadHash,
    constitutionVersion: input.constitutionVersion,
    governanceContext: input.governanceContext,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce ?? randomUUID(),
    provenance: "giia-authoritative-pipeline",
    signingAuthorityId: input.authorization.signingAuthorityId,
    governanceKeyId: input.authorization.governanceKey.id,
    governanceAuthorizationId:
      input.authorization.authorization.payload.authorizationId,
    governanceAuthorizationFingerprint: authorizationFingerprint,
  };

  const signatureBase64 = input.boundary.sign(
    input.authorization.governanceKey.id,
    "governance",
    payload,
    input.issuedAt,
  );

  return {
    payload,
    signingAlgorithm: "Ed25519",
    signatureBase64,
  };
}

export function verifySignedGovernanceDecision(
  input: VerifyGovernanceDecisionInput,
): GovernanceDecisionVerificationResult {
  try {
    const {
      decision,
      authorization,
      governanceKey,
      credential,
      trustChain,
      at,
    } = input;

    if (decision.signingAlgorithm !== "Ed25519") {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_ALGORITHM_INVALID",
      };
    }

    if (decision.payload.decision !== "ALLOW") {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_NOT_ALLOW",
      };
    }

    if (decision.payload.provenance !== "giia-authoritative-pipeline") {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_PROVENANCE_INVALID",
      };
    }

    if (decision.payload.issuedAt > at) {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_NOT_YET_VALID",
      };
    }

    if (at >= decision.payload.expiresAt) {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_EXPIRED",
      };
    }

    if (
      decision.payload.governanceKeyId.length === 0 ||
      decision.payload.governanceAuthorizationId.length === 0 ||
      decision.payload.signingAuthorityId.length === 0 ||
      decision.payload.governanceAuthorizationFingerprint.length === 0
    ) {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_AUTHORITY_BINDING_INVALID",
      };
    }

    if (governanceKey.purpose !== "governance") {
      return {
        valid: false,
        reason: "GOVERNANCE_KEY_PURPOSE_INVALID",
      };
    }

    if (governanceKey.status !== "active") {
      return {
        valid: false,
        reason: "GOVERNANCE_KEY_NOT_ACTIVE",
      };
    }

    if (decision.payload.governanceKeyId !== governanceKey.id) {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_KEY_ID_MISMATCH",
      };
    }

    if (
      decision.payload.governanceAuthorizationId !==
      authorization.payload.authorizationId
    ) {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_AUTHORIZATION_ID_MISMATCH",
      };
    }

    if (
      decision.payload.signingAuthorityId !==
      authorization.payload.signingAuthorityId
    ) {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_SIGNING_AUTHORITY_MISMATCH",
      };
    }

    if (
      decision.payload.governanceKeyId !==
      authorization.payload.governanceKeyId
    ) {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_AUTHORIZATION_KEY_MISMATCH",
      };
    }

    const authorizationFingerprint =
      governanceKeyAuthorizationFingerprint(authorization);

    if (
      decision.payload.governanceAuthorizationFingerprint !==
      authorizationFingerprint
    ) {
      return {
        valid: false,
        reason: "GOVERNANCE_DECISION_AUTHORIZATION_FINGERPRINT_INVALID",
      };
    }

    const authorizationValid = verifyGovernanceKeyAuthorization({
      authorization,
      governanceKey,
      credential,
      trustChain,
      at,
    });

    if (!authorizationValid) {
      return {
        valid: false,
        reason: "GOVERNANCE_AUTHORIZATION_INVALID",
      };
    }

    const valid = verifyCanonical(
      decision.payload,
      decision.signatureBase64,
      governanceKey.publicKeyPem,
    );

    return valid
      ? {
          valid: true,
          reason: "GOVERNANCE_DECISION_VERIFIED",
        }
      : {
          valid: false,
          reason: "GOVERNANCE_DECISION_SIGNATURE_INVALID",
        };
  } catch {
    return {
      valid: false,
      reason: "GOVERNANCE_DECISION_VERIFICATION_FAILED",
    };
  }
}

export function governanceDecisionFingerprint(
  decision: SignedGovernanceDecision,
): string {
  return sha256Canonical(decision.payload);
}
