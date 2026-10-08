import { invariant } from "../core/errors.js";
import { canonicalize } from "../core/canonical.js";
import { sha256 } from "../core/security.js";
import {
  verifyTrustChain,
  type TrustChainInput,
} from "./service.js";
import {
  authenticateVerifier,
  verifyAuthenticatedVerifier,
  type AuthenticatedVerifier,
} from "./verifier.js";
import type { TrustVerificationResult } from "./types.js";

export interface AuthenticatedVerificationEvidence {
  id: string;
  subjectId: string;
  verifiedAt: string;
  verifierId: string;
  verifierAuthenticationHash: string;
  verifierTrustChain: string[];
  verifierTrustChainInput: TrustChainInput;
  trustChain: string[];
  trustChainInput: TrustChainInput;
  trustResult: TrustVerificationResult;
  evidenceHash: string;
}

export interface CreateAuthenticatedVerificationInput {
  id: string;
  subjectId: string;
  verifier: AuthenticatedVerifier;
  verifiedAt: string;
  chain: TrustChainInput;
}

function evidencePayload(
  evidence: Omit<AuthenticatedVerificationEvidence, "evidenceHash">,
): Omit<AuthenticatedVerificationEvidence, "evidenceHash"> {
  return evidence;
}

function cloneTrustChainInput(input: TrustChainInput): TrustChainInput {
  return {
    ...input,
    root: { ...input.root },
    rootKey: { ...input.rootKey },
    anchor: {
      ...input.anchor,
      constraints: [...input.anchor.constraints],
    },
    anchorKey: { ...input.anchorKey },
    delegation: {
      ...input.delegation,
      constraints: [...input.delegation.constraints],
    },
    delegationKey: { ...input.delegationKey },
    credential: {
      ...input.credential,
      claims: { ...input.credential.claims },
    },
  };
}

export function createAuthenticatedVerification(
  input: CreateAuthenticatedVerificationInput,
): AuthenticatedVerificationEvidence {
  invariant(
    input.id.trim().length > 0,
    "VERIFICATION_ID_EMPTY",
    "Verification id is required",
  );

  invariant(
    input.subjectId.trim().length > 0,
    "VERIFICATION_SUBJECT_EMPTY",
    "Verification subject id is required",
  );

  invariant(
    input.verifiedAt.trim().length > 0,
    "VERIFICATION_TIME_EMPTY",
    "Verification timestamp is required",
  );

  invariant(
    input.verifiedAt === input.chain.at,
    "VERIFICATION_TIME_MISMATCH",
    "Verification timestamp must match trust-chain verification time",
  );

  invariant(
    verifyAuthenticatedVerifier(input.verifier, input.verifiedAt),
    "VERIFIER_AUTHENTICATION_INVALID",
    "Verifier authentication evidence is invalid",
  );

  const verifierTrust = verifyTrustChain(input.chain);

  invariant(
    verifierTrust.valid,
    "TRUST_CHAIN_VERIFICATION_FAILED",
    `Subject trust chain verification failed: ${verifierTrust.reason}`,
  );

  invariant(
    input.chain.credential.subject === input.subjectId,
    "VERIFICATION_SUBJECT_BINDING_INVALID",
    "Verification subject does not match credential subject",
  );

  const unsigned: Omit<
    AuthenticatedVerificationEvidence,
    "evidenceHash"
  > = {
    id: input.id,
    subjectId: input.subjectId,
    verifiedAt: input.verifiedAt,
    verifierId: input.verifier.verifierId,
    verifierAuthenticationHash: input.verifier.authenticationHash,
    verifierTrustChain: [...input.verifier.trustChain],
    verifierTrustChainInput: cloneTrustChainInput(
      input.verifier.trustChainInput,
    ),
    trustChain: [...verifierTrust.chain],
    trustChainInput: cloneTrustChainInput(input.chain),
    trustResult: verifierTrust,
  };

  return {
    ...unsigned,
    evidenceHash: sha256(canonicalize(evidencePayload(unsigned))),
  };
}

export function verifyAuthenticatedVerificationEvidence(
  evidence: AuthenticatedVerificationEvidence,
  expectedSubjectId: string,
  expectedAt: string,
): boolean {
  if (evidence.subjectId !== expectedSubjectId) return false;
  if (evidence.verifiedAt !== expectedAt) return false;
  if (!evidence.trustResult.valid) return false;
  if (evidence.verifierId.trim().length === 0) return false;
  if (evidence.verifierAuthenticationHash.trim().length === 0) {
    return false;
  }
  if (evidence.verifierTrustChain.length === 0) return false;
  if (evidence.trustChain.length === 0) return false;

  if (!evidence.verifierTrustChainInput) return false;
  if (!evidence.trustChainInput) return false;

  if (evidence.verifierTrustChainInput.at !== evidence.verifiedAt) {
    return false;
  }

  if (evidence.trustChainInput.at !== evidence.verifiedAt) {
    return false;
  }

  if (
    evidence.verifierTrustChainInput.credential.subject !==
    evidence.verifierId
  ) {
    return false;
  }

  if (
    evidence.trustChainInput.credential.subject !==
    evidence.subjectId
  ) {
    return false;
  }

  const verifierTrust = verifyTrustChain(
    evidence.verifierTrustChainInput,
  );

  if (!verifierTrust.valid) return false;

  if (
    JSON.stringify(verifierTrust.chain) !==
    JSON.stringify(evidence.verifierTrustChain)
  ) {
    return false;
  }

  const subjectTrust = verifyTrustChain(
    evidence.trustChainInput,
  );

  if (!subjectTrust.valid) return false;

  if (
    JSON.stringify(subjectTrust.chain) !==
    JSON.stringify(evidence.trustChain)
  ) {
    return false;
  }

  const unsigned: Omit<
    AuthenticatedVerificationEvidence,
    "evidenceHash"
  > = {
    id: evidence.id,
    subjectId: evidence.subjectId,
    verifiedAt: evidence.verifiedAt,
    verifierId: evidence.verifierId,
    verifierAuthenticationHash: evidence.verifierAuthenticationHash,
    verifierTrustChain: [...evidence.verifierTrustChain],
    verifierTrustChainInput: cloneTrustChainInput(
      evidence.verifierTrustChainInput,
    ),
    trustChain: [...evidence.trustChain],
    trustChainInput: cloneTrustChainInput(evidence.trustChainInput),
    trustResult: evidence.trustResult,
  };

  return (
    sha256(canonicalize(evidencePayload(unsigned))) ===
    evidence.evidenceHash
  );
}

export { authenticateVerifier, verifyAuthenticatedVerifier };
