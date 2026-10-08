import { invariant } from "../core/errors.js";
import { canonicalize } from "../core/canonical.js";
import { sha256 } from "../core/security.js";
import { authorize } from "../authorization/service.js";
import type { AuthorizationRequest } from "../authorization/types.js";
import type { Authority } from "../authority/types.js";
import type { Identity } from "../identity/types.js";
import {
  verifyTrustChain,
  type TrustChainInput,
} from "./service.js";

export const VERIFIER_AUTHORITY_CLAIM = "giia.verifier.authority";
export const VERIFIER_AUTHORITY_HASH_CLAIM = "giia.verifier.authorityHash";

export interface AuthenticatedVerifier {
  verifierId: string;
  identity: Identity;
  authority: Authority;
  trustChain: string[];
  trustChainInput: TrustChainInput;
  authorityHash: string;
  authorizationRequest: AuthorizationRequest;
  authenticatedAt: string;
  authenticationHash: string;
}

export interface AuthenticateVerifierInput {
  identity: Identity;
  authority: Authority;
  chain: TrustChainInput;
  authorizationRequest: AuthorizationRequest;
}

function authorityFingerprint(authority: Authority): string {
  return sha256(canonicalize(authority));
}

function verifierPayload(
  verifier: Omit<AuthenticatedVerifier, "authenticationHash">,
): Omit<AuthenticatedVerifier, "authenticationHash"> {
  return verifier;
}

export function authenticateVerifier(
  input: AuthenticateVerifierInput,
): AuthenticatedVerifier {
  invariant(
    input.chain.credential.subject === input.identity.id,
    "VERIFIER_IDENTITY_CHAIN_MISMATCH",
    "Verifier identity does not match authenticated trust credential",
  );

  invariant(
    input.authority.holderIdentityId === input.identity.id,
    "VERIFIER_AUTHORITY_HOLDER_MISMATCH",
    "Verifier authority is not held by the authenticated verifier identity",
  );

  invariant(
    input.authorizationRequest.subjectIdentityId === input.identity.id,
    "VERIFIER_AUTHORIZATION_SUBJECT_MISMATCH",
    "Authorization subject does not match verifier identity",
  );

  invariant(
    input.authorizationRequest.authorityId === input.authority.id,
    "VERIFIER_AUTHORIZATION_AUTHORITY_MISMATCH",
    "Authorization authority does not match verifier authority",
  );

  invariant(
    input.authorizationRequest.requestedAt === input.chain.at,
    "VERIFIER_AUTHORIZATION_TIME_MISMATCH",
    "Verifier authorization time does not match trust verification time",
  );

  const trustResult = verifyTrustChain(input.chain);

  invariant(
    trustResult.valid,
    "VERIFIER_TRUST_CHAIN_INVALID",
    `Verifier trust chain invalid: ${trustResult.reason}`,
  );

  const authorityHash = authorityFingerprint(input.authority);

  invariant(
    input.chain.credential.claims[VERIFIER_AUTHORITY_CLAIM] ===
      input.authority.id,
    "VERIFIER_AUTHORITY_CLAIM_MISMATCH",
    "Authenticated credential does not bind the verifier authority id",
  );

  invariant(
    input.chain.credential.claims[VERIFIER_AUTHORITY_HASH_CLAIM] ===
      authorityHash,
    "VERIFIER_AUTHORITY_HASH_MISMATCH",
    "Authenticated credential does not bind the verifier authority contents",
  );

  const authorization = authorize(
    input.authorizationRequest,
    input.identity,
    input.authority,
  );

  invariant(
    authorization.decision === "ALLOW",
    "VERIFIER_NOT_AUTHORIZED",
    `Verifier authorization denied: ${authorization.reason}`,
  );

  const unsigned: Omit<
    AuthenticatedVerifier,
    "authenticationHash"
  > = {
    verifierId: input.identity.id,
    identity: { ...input.identity },
    authority: { ...input.authority, scope: [...input.authority.scope] },
    trustChain: [...trustResult.chain],
    trustChainInput: {
      ...input.chain,
      root: { ...input.chain.root },
      rootKey: { ...input.chain.rootKey },
      anchor: {
        ...input.chain.anchor,
        constraints: [...input.chain.anchor.constraints],
      },
      anchorKey: { ...input.chain.anchorKey },
      delegation: {
        ...input.chain.delegation,
        constraints: [...input.chain.delegation.constraints],
      },
      delegationKey: { ...input.chain.delegationKey },
      credential: {
        ...input.chain.credential,
        claims: { ...input.chain.credential.claims },
      },
    },
    authorityHash,
    authorizationRequest: {
      ...input.authorizationRequest,
    },
    authenticatedAt: input.chain.at,
  };

  return {
    ...unsigned,
    authenticationHash: sha256(canonicalize(verifierPayload(unsigned))),
  };
}

export function verifyAuthenticatedVerifier(
  verifier: AuthenticatedVerifier,
  expectedAt: string,
): boolean {
  if (verifier.verifierId !== verifier.identity.id) return false;

  if (verifier.identity.status !== "active") return false;

  if (verifier.authority.holderIdentityId !== verifier.identity.id) {
    return false;
  }

  if (verifier.authenticatedAt !== expectedAt) return false;

  if (verifier.trustChainInput.at !== expectedAt) return false;

  if (
    verifier.trustChainInput.credential.subject !==
    verifier.identity.id
  ) {
    return false;
  }

  if (verifier.authorizationRequest.subjectIdentityId !== verifier.identity.id) {
    return false;
  }

  if (verifier.authorizationRequest.authorityId !== verifier.authority.id) {
    return false;
  }

  if (verifier.authorizationRequest.requestedAt !== expectedAt) {
    return false;
  }

  if (verifier.authorizationRequest.action !== "VERIFY") {
    return false;
  }

  if (verifier.authorityHash !== authorityFingerprint(verifier.authority)) {
    return false;
  }

  const trustResult = verifyTrustChain(verifier.trustChainInput);

  if (!trustResult.valid) return false;

  if (
    JSON.stringify(trustResult.chain) !==
    JSON.stringify(verifier.trustChain)
  ) {
    return false;
  }

  if (
    verifier.trustChainInput.credential.claims[VERIFIER_AUTHORITY_CLAIM] !==
    verifier.authority.id
  ) {
    return false;
  }

  if (
    verifier.trustChainInput.credential.claims[
      VERIFIER_AUTHORITY_HASH_CLAIM
    ] !== verifier.authorityHash
  ) {
    return false;
  }

  const unsigned: Omit<
    AuthenticatedVerifier,
    "authenticationHash"
  > = {
    verifierId: verifier.verifierId,
    identity: { ...verifier.identity },
    authority: {
      ...verifier.authority,
      scope: [...verifier.authority.scope],
    },
    trustChain: [...verifier.trustChain],
    trustChainInput: {
      ...verifier.trustChainInput,
      root: { ...verifier.trustChainInput.root },
      rootKey: { ...verifier.trustChainInput.rootKey },
      anchor: {
        ...verifier.trustChainInput.anchor,
        constraints: [...verifier.trustChainInput.anchor.constraints],
      },
      anchorKey: { ...verifier.trustChainInput.anchorKey },
      delegation: {
        ...verifier.trustChainInput.delegation,
        constraints: [...verifier.trustChainInput.delegation.constraints],
      },
      delegationKey: { ...verifier.trustChainInput.delegationKey },
      credential: {
        ...verifier.trustChainInput.credential,
        claims: { ...verifier.trustChainInput.credential.claims },
      },
    },
    authorityHash: verifier.authorityHash,
    authorizationRequest: {
      ...verifier.authorizationRequest,
    },
    authenticatedAt: verifier.authenticatedAt,
  };

  return (
    sha256(canonicalize(verifierPayload(unsigned))) ===
    verifier.authenticationHash
  );
}
