import type {
  TrustCredential,
  TrustKey,
  TrustVerificationResult,
} from "../trust/types.js";
import {
  verifyCanonical,
} from "../trust/crypto.js";
import {
  verifyTrustChain,
} from "../trust/service.js";
import type { TrustChainInput } from "../trust/service.js";
import { createHash } from "node:crypto";
import { canonicalize } from "../core/canonical.js";
import { invariant } from "../core/errors.js";
import type { KeySecurityBoundary } from "../security/key-boundary.js";

export interface GovernanceKeyAuthorizationPayload {
  readonly authorizationId: string;
  readonly governanceKeyId: string;
  readonly governancePublicKeyPem: string;
  readonly governanceScope: "DECISION_SIGNING";
  readonly credentialId: string;
  readonly signingAuthorityId: string;
  readonly issuerDelegationId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly provenance: "giia-governance-key-authorization";
}

export interface SignedGovernanceKeyAuthorization {
  readonly payload: GovernanceKeyAuthorizationPayload;
  readonly signingAlgorithm: "Ed25519";
  readonly issuerDelegationKeyId: string;
  readonly signatureBase64: string;
}

export interface GovernanceKeyAuthorizationInput {
  readonly authorizationId: string;
  readonly governanceKey: TrustKey;
  readonly credential: TrustCredential;
  readonly signingAuthorityId: string;
  readonly issuerDelegationKey: TrustKey;
  readonly trustChain: TrustChainInput;
  readonly boundary: KeySecurityBoundary;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

function validateGovernanceAuthorizationInputs(
  input: GovernanceKeyAuthorizationInput,
): TrustVerificationResult {
  invariant(
    input.governanceKey.algorithm === "Ed25519",
    "GOVERNANCE_KEY_ALGORITHM_INVALID",
    "Governance decision signing requires Ed25519",
  );

  invariant(
    input.governanceKey.purpose === "governance",
    "GOVERNANCE_KEY_PURPOSE_INVALID",
    "Only governance-purpose keys can receive governance decision authorization",
  );

  invariant(
    input.governanceKey.status === "active",
    "GOVERNANCE_KEY_NOT_ACTIVE",
    "Governance key must be active",
  );

  invariant(
    input.credential.status === "active",
    "GOVERNANCE_CREDENTIAL_NOT_ACTIVE",
    "Governance credential must be active",
  );

  invariant(
    input.credential.subject === input.signingAuthorityId,
    "GOVERNANCE_SIGNING_AUTHORITY_MISMATCH",
    "Governance credential subject must match signing authority",
  );

  invariant(
    input.credential.claims["governance:policy"] === "true" ||
      input.credential.claims["governance:constitutional"] === "true",
    "GOVERNANCE_DECISION_AUTHORIZATION_MISSING",
    "Credential does not authorize governance decision authority",
  );

  invariant(
    input.credential.issuerDelegationId ===
      input.issuerDelegationKey.id ||
      input.trustChain.delegationKey.id === input.issuerDelegationKey.id,
    "GOVERNANCE_ISSUER_KEY_BINDING_INVALID",
    "Governance authorization issuer key is not bound to the supplied trust chain",
  );

  invariant(
    input.trustChain.credential.id === input.credential.id,
    "GOVERNANCE_CREDENTIAL_CHAIN_MISMATCH",
    "Governance credential does not match the supplied trust chain",
  );

  invariant(
    input.trustChain.delegationKey.id === input.issuerDelegationKey.id,
    "GOVERNANCE_DELEGATION_KEY_CHAIN_MISMATCH",
    "Governance issuer key does not match the verified delegation key",
  );

  invariant(
    input.expiresAt > input.issuedAt,
    "GOVERNANCE_KEY_AUTHORIZATION_WINDOW_INVALID",
    "Governance key authorization expiry must follow issuance",
  );

  const trust = verifyTrustChain({
    ...input.trustChain,
    at: input.issuedAt,
  });

  invariant(
    trust.valid,
    "GOVERNANCE_TRUST_CHAIN_INVALID",
    `Governance trust chain invalid: ${trust.reason}`,
  );

  return trust;
}

export function createGovernanceKeyAuthorization(
  input: GovernanceKeyAuthorizationInput,
): SignedGovernanceKeyAuthorization {
  validateGovernanceAuthorizationInputs(input);

  const payload: GovernanceKeyAuthorizationPayload = {
    authorizationId: input.authorizationId,
    governanceKeyId: input.governanceKey.id,
    governancePublicKeyPem: input.governanceKey.publicKeyPem,
    governanceScope: "DECISION_SIGNING",
    credentialId: input.credential.id,
    signingAuthorityId: input.signingAuthorityId,
    issuerDelegationId: input.credential.issuerDelegationId,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    provenance: "giia-governance-key-authorization",
  };

  const signatureBase64 = input.boundary.sign(
    input.issuerDelegationKey.id,
    "delegation",
    payload,
    input.issuedAt,
  );

  return {
    payload,
    signingAlgorithm: "Ed25519",
    issuerDelegationKeyId: input.issuerDelegationKey.id,
    signatureBase64,
  };
}

export interface GovernanceKeyAuthorizationVerificationInput {
  readonly authorization: SignedGovernanceKeyAuthorization;
  readonly governanceKey: TrustKey;
  readonly credential: TrustCredential;
  readonly trustChain: TrustChainInput;
  readonly at: string;
}

export function verifyGovernanceKeyAuthorization(
  input: GovernanceKeyAuthorizationVerificationInput,
): boolean {
  try {
    const {
      authorization,
      governanceKey,
      credential,
      trustChain,
      at,
    } = input;

    const payload = authorization.payload;

    if (authorization.signingAlgorithm !== "Ed25519") return false;

    if (
      payload.provenance !==
      "giia-governance-key-authorization"
    ) {
      return false;
    }

    if (payload.governanceScope !== "DECISION_SIGNING") {
      return false;
    }

    if (payload.governanceKeyId !== governanceKey.id) {
      return false;
    }

    if (
      payload.governancePublicKeyPem !==
      governanceKey.publicKeyPem
    ) {
      return false;
    }

    if (governanceKey.algorithm !== "Ed25519") {
      return false;
    }

    if (governanceKey.purpose !== "governance") {
      return false;
    }

    if (governanceKey.status !== "active") {
      return false;
    }

    if (payload.credentialId !== credential.id) {
      return false;
    }

    if (
      payload.signingAuthorityId !==
      credential.subject
    ) {
      return false;
    }

    if (
      payload.issuerDelegationId !==
      credential.issuerDelegationId
    ) {
      return false;
    }

    if (
      authorization.issuerDelegationKeyId !==
      trustChain.delegationKey.id
    ) {
      return false;
    }

    if (
      trustChain.credential.id !== credential.id
    ) {
      return false;
    }

    if (
      trustChain.delegationKey.id !==
      authorization.issuerDelegationKeyId
    ) {
      return false;
    }

    if (credential.status !== "active") {
      return false;
    }

    if (
      credential.claims["governance:policy"] !== "true" &&
      credential.claims["governance:constitutional"] !== "true"
    ) {
      return false;
    }

    if (payload.issuedAt > at) {
      return false;
    }

    if (at >= payload.expiresAt) {
      return false;
    }

    const trust = verifyTrustChain({
      ...trustChain,
      credential,
      at,
    });

    if (!trust.valid) {
      return false;
    }

    if (
      trustChain.delegationKey.id !==
      authorization.issuerDelegationKeyId
    ) {
      return false;
    }

    if (
      trustChain.delegationKey.status !== "active"
    ) {
      return false;
    }

    if (
      at < trustChain.delegationKey.notBefore
    ) {
      return false;
    }

    if (
      trustChain.delegationKey.notAfter !==
        undefined &&
      at >= trustChain.delegationKey.notAfter
    ) {
      return false;
    }

    return verifyCanonical(
      payload,
      authorization.signatureBase64,
      trustChain.delegationKey.publicKeyPem,
    );
  } catch {
    return false;
  }
}

export function governanceKeyAuthorizationFingerprint(
  authorization: SignedGovernanceKeyAuthorization,
): string {
  return createHash("sha256")
    .update(canonicalize(authorization.payload), "utf8")
    .digest("hex");
}
