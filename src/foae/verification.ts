import { validateTimestamp } from "../core/validation.js";
import { hasScope, isUsableAuthority, validateAuthority } from "../authority/service.js";
import type { Authority } from "../authority/types.js";
import { verifyEvidenceChain } from "../evidence/chain.js";
import type { Evidence } from "../evidence/types.js";
import { TrustRegistry } from "../trust/registry.js";
import {
  verifyAuthenticatedVerificationEvidence,
} from "../trust/verification.js";
import type { AuthenticatedVerificationEvidence } from "../trust/verification.js";
import type { TrustChainInput } from "../trust/service.js";
import {
  createProducerOriginResultHash,
  validateProducerOriginClaim,
} from "./service.js";
import type {
  FOAEVerificationStatus,
  ProducerOriginClaim,
  ProducerOriginVerificationResult,
} from "./types.js";

export const FOAE_PRODUCER_AUTHORITY_CLAIM =
  "giia.foae.producerAuthority";

export const FOAE_PRODUCER_AUTHORITY_HASH_CLAIM =
  "giia.foae.producerAuthorityHash";

export const FOAE_ARTIFACT_ID_CLAIM =
  "giia.foae.artifactId";

export const FOAE_ARTIFACT_HASH_CLAIM =
  "giia.foae.artifactHash";

export const FOAE_ARTIFACT_VERSION_CLAIM =
  "giia.foae.artifactVersion";

export const FOAE_ARTIFACT_TYPE_CLAIM =
  "giia.foae.artifactType";

export const FOAE_ORGANIZATION_ID_CLAIM =
  "giia.foae.organizationId";

export const FOAE_ORIGIN_SCOPE_PREFIX =
  "ORIGIN:";

export interface VerifyProducerOriginInput {
  claim: ProducerOriginClaim;
  producerAuthority: Authority;
  evidenceChain: Evidence[];
  authenticatedVerification: AuthenticatedVerificationEvidence;
  verifiedAt: string;
  trustRegistry: TrustRegistry;
}

function result(
  input: VerifyProducerOriginInput,
  status: FOAEVerificationStatus,
  reason: string,
  evidenceChainFinalHash?: string,
): ProducerOriginVerificationResult {
  const unsigned: Omit<
    ProducerOriginVerificationResult,
    "resultHash"
  > = {
    claimId: input.claim.id,
    artifactId: input.claim.artifactId,
    producerId: input.claim.claimedProducerId,
    verifierId: input.authenticatedVerification.verifierId,
    verifiedAt: input.verifiedAt,
    status,
    reason,
    authenticatedVerificationEvidenceId:
      input.authenticatedVerification.id,
    producerAuthorityRef: input.claim.producerAuthorityRef,
    originalArtifactHash: input.claim.originalArtifactHash,
  };

  if (evidenceChainFinalHash !== undefined) {
    unsigned.evidenceChainFinalHash = evidenceChainFinalHash;
  }

  return {
    ...unsigned,
    resultHash: createProducerOriginResultHash(unsigned),
  };
}

function safeResult(
  input: VerifyProducerOriginInput,
  status: FOAEVerificationStatus,
  reason: string,
  evidenceChainFinalHash?: string,
): ProducerOriginVerificationResult {
  return result(input, status, reason, evidenceChainFinalHash);
}

function currentChainRevoked(
  registry: TrustRegistry,
  chain: TrustChainInput,
): boolean {
  return (
    registry.isRevoked("key", chain.rootKey.id) ||
    registry.isRevoked("key", chain.anchorKey.id) ||
    registry.isRevoked("key", chain.delegationKey.id) ||
    registry.isRevoked("root", chain.root.id) ||
    registry.isRevoked("anchor", chain.anchor.id) ||
    registry.isRevoked("delegation", chain.delegation.id) ||
    registry.isRevoked("credential", chain.credential.id)
  );
}

function currentChainObjectsExist(
  registry: TrustRegistry,
  chain: TrustChainInput,
): boolean {
  return (
    registry.getKey(chain.rootKey.id) !== undefined &&
    registry.getKey(chain.anchorKey.id) !== undefined &&
    registry.getKey(chain.delegationKey.id) !== undefined &&
    registry.getRoot(chain.root.id) !== undefined &&
    registry.getAnchor(chain.anchor.id) !== undefined &&
    registry.getDelegation(chain.delegation.id) !== undefined &&
    registry.getCredential(chain.credential.id) !== undefined
  );
}

export function verifyProducerOrigin(
  input: VerifyProducerOriginInput,
): ProducerOriginVerificationResult {
  try {
    validateProducerOriginClaim(input.claim);
    validateAuthority(input.producerAuthority);

    validateTimestamp(
      input.verifiedAt,
      "FOAE_VERIFY_TIME_INVALID",
      "FOAE verification time must be valid",
    );

    if (input.verifiedAt < input.claim.validFrom) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_VERIFY_BEFORE_VALIDITY",
      );
    }

    if (
      input.claim.validUntil !== undefined &&
      input.verifiedAt >= input.claim.validUntil
    ) {
      return safeResult(
        input,
        "EXPIRED",
        "PRODUCER_ORIGIN_CLAIM_EXPIRED",
      );
    }

    if (
      input.producerAuthority.id !== input.claim.producerAuthorityRef
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "PRODUCER_AUTHORITY_REFERENCE_MISMATCH",
      );
    }

    if (
      input.producerAuthority.holderIdentityId !==
      input.claim.claimedProducerId
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "PRODUCER_AUTHORITY_HOLDER_MISMATCH",
      );
    }

    if (
      !isUsableAuthority(
        input.producerAuthority,
        input.verifiedAt,
      )
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "PRODUCER_AUTHORITY_NOT_USABLE",
      );
    }

    if (
      !hasScope(
        input.producerAuthority,
        FOAE_ORIGIN_SCOPE_PREFIX.slice(0, -1),
        input.claim.artifactId,
      )
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "PRODUCER_AUTHORITY_ORIGIN_SCOPE_MISSING",
      );
    }

    const authenticatedVerificationValid =
      verifyAuthenticatedVerificationEvidence(
        input.authenticatedVerification,
        input.claim.claimedProducerId,
        input.verifiedAt,
      );

    if (!authenticatedVerificationValid) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_AUTHENTICATED_VERIFICATION_INVALID",
      );
    }

    const producerChain =
      input.authenticatedVerification.trustChainInput;

    const producerCredential =
      producerChain.credential;

    const claims = producerCredential.claims;

    if (
      claims[FOAE_PRODUCER_AUTHORITY_CLAIM] !==
      input.producerAuthority.id
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_PRODUCER_AUTHORITY_CLAIM_MISMATCH",
      );
    }

    if (
      claims[FOAE_ARTIFACT_ID_CLAIM] !==
      input.claim.artifactId
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_ARTIFACT_ID_CLAIM_MISMATCH",
      );
    }

    if (
      claims[FOAE_ARTIFACT_HASH_CLAIM] !==
      input.claim.originalArtifactHash
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_ARTIFACT_HASH_CLAIM_MISMATCH",
      );
    }

    if (
      claims[FOAE_ARTIFACT_VERSION_CLAIM] !==
      input.claim.artifactVersion
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_ARTIFACT_VERSION_CLAIM_MISMATCH",
      );
    }

    if (
      claims[FOAE_ARTIFACT_TYPE_CLAIM] !==
      input.claim.artifactType
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_ARTIFACT_TYPE_CLAIM_MISMATCH",
      );
    }

    if (
      claims[FOAE_ORGANIZATION_ID_CLAIM] !==
      input.claim.organizationId
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_ORGANIZATION_CLAIM_MISMATCH",
      );
    }

    /*
     * The authority hash must be cryptographically bound through the
     * existing GIIA canonical hash primitive. The producer credential
     * itself must carry that exact binding.
     */
    const expectedAuthorityHash =
      canonicalAuthorityHashValue(input.producerAuthority);

    if (
      claims[FOAE_PRODUCER_AUTHORITY_HASH_CLAIM] !==
      expectedAuthorityHash
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_PRODUCER_AUTHORITY_HASH_MISMATCH",
      );
    }

    if (
      producerCredential.subject !==
      input.claim.claimedProducerId
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_PRODUCER_CREDENTIAL_SUBJECT_MISMATCH",
      );
    }

    if (
      !currentChainObjectsExist(
        input.trustRegistry,
        producerChain,
      )
    ) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "FOAE_CURRENT_TRUST_STATE_UNAVAILABLE",
      );
    }

    if (
      currentChainRevoked(
        input.trustRegistry,
        producerChain,
      )
    ) {
      return safeResult(
        input,
        "REVOKED",
        "PRODUCER_ORIGIN_CURRENT_TRUST_REVOKED",
      );
    }

    const evidenceVerification =
      verifyEvidenceChain(input.evidenceChain);

    if (!evidenceVerification.valid) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        evidenceVerification.reason,
        evidenceVerification.finalHash,
      );
    }

    const hasArtifactEvidence =
      input.evidenceChain.some(
        (evidence) =>
          evidence.subject === input.claim.artifactId &&
          evidence.contentHash ===
            input.claim.originalArtifactHash,
      );

    if (!hasArtifactEvidence) {
      return safeResult(
        input,
        "UNVERIFIABLE",
        "ARTIFACT_ORIGIN_EVIDENCE_NOT_BOUND",
        evidenceVerification.finalHash,
      );
    }

    return safeResult(
      input,
      "VERIFIED",
      "PRODUCER_ORIGIN_VERIFIED",
      evidenceVerification.finalHash,
    );
  } catch {
    return safeResult(
      input,
      "UNVERIFIABLE",
      "FOAE_VERIFICATION_INPUT_INVALID",
    );
  }
}

/*
 * This import-compatible helper is replaced by the canonical GIIA hash
 * implementation below through a local static import.
 */
import { canonicalize } from "../core/canonical.js";
import { sha256 } from "../core/security.js";

function canonicalAuthorityHashValue(
  authority: Authority,
): string {
  return sha256(canonicalize(authority));
}
