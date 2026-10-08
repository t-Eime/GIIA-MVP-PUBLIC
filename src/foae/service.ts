import { invariant } from "../core/errors.js";
import { canonicalHash } from "../core/canonical.js";
import { validateTimestamp } from "../core/validation.js";
import type {
  FOAEObservation,
  ProducerAssurance,
  ProducerOriginClaim,
  ProducerOriginEvidence,
  ProducerOriginVerificationResult,
} from "./types.js";

function nonEmpty(value: string, code: string, message: string): void {
  invariant(value.trim().length > 0, code, message);
}

function validateObservation(observation: FOAEObservation): void {
  nonEmpty(observation.id, "FOAE_OBSERVATION_ID_EMPTY", "FOAE observation id is required");
  nonEmpty(
    observation.statement,
    "FOAE_OBSERVATION_STATEMENT_EMPTY",
    "FOAE observation statement is required",
  );
  nonEmpty(
    observation.source,
    "FOAE_OBSERVATION_SOURCE_EMPTY",
    "FOAE observation source is required",
  );
  nonEmpty(
    observation.observedAt,
    "FOAE_OBSERVATION_TIME_EMPTY",
    "FOAE observation timestamp is required",
  );
  nonEmpty(
    observation.provenance,
    "FOAE_OBSERVATION_PROVENANCE_EMPTY",
    "FOAE observation provenance is required",
  );

  validateTimestamp(
    observation.observedAt,
    "FOAE_OBSERVATION_TIME_INVALID",
    "FOAE observation timestamp must be valid",
  );

  if (observation.evidenceRef !== undefined) {
    nonEmpty(
      observation.evidenceRef,
      "FOAE_OBSERVATION_EVIDENCE_REF_EMPTY",
      "FOAE observation evidence reference cannot be empty",
    );
  }
}

function validateProducerAssurance(assurance: ProducerAssurance): void {
  nonEmpty(
    assurance.declaredBy,
    "FOAE_ASSURANCE_DECLARER_EMPTY",
    "Producer assurance declarer is required",
  );
  nonEmpty(
    assurance.declarationRef,
    "FOAE_ASSURANCE_REF_EMPTY",
    "Producer assurance declaration reference is required",
  );
  nonEmpty(
    assurance.scope,
    "FOAE_ASSURANCE_SCOPE_EMPTY",
    "Producer assurance scope is required",
  );
  nonEmpty(
    assurance.terms,
    "FOAE_ASSURANCE_TERMS_EMPTY",
    "Producer assurance terms are required",
  );
  nonEmpty(
    assurance.effectiveFrom,
    "FOAE_ASSURANCE_EFFECTIVE_FROM_EMPTY",
    "Producer assurance effective time is required",
  );
  nonEmpty(
    assurance.provenance,
    "FOAE_ASSURANCE_PROVENANCE_EMPTY",
    "Producer assurance provenance is required",
  );

  validateTimestamp(
    assurance.effectiveFrom,
    "FOAE_ASSURANCE_EFFECTIVE_FROM_INVALID",
    "Producer assurance effective time must be valid",
  );

  if (assurance.effectiveUntil !== undefined) {
    validateTimestamp(
      assurance.effectiveUntil,
      "FOAE_ASSURANCE_EFFECTIVE_UNTIL_INVALID",
      "Producer assurance end time must be valid",
    );

    invariant(
      assurance.effectiveUntil > assurance.effectiveFrom,
      "FOAE_ASSURANCE_WINDOW_INVALID",
      "Producer assurance end must be after its start",
    );
  }
}

export function validateProducerOriginClaim(
  claim: ProducerOriginClaim,
): void {
  nonEmpty(claim.id, "FOAE_ID_EMPTY", "FOAE claim id is required");
  nonEmpty(
    claim.organizationId,
    "FOAE_ORGANIZATION_EMPTY",
    "FOAE organization id is required",
  );
  nonEmpty(
    claim.artifactId,
    "FOAE_ARTIFACT_ID_EMPTY",
    "FOAE artifact id is required",
  );
  nonEmpty(
    claim.artifactType,
    "FOAE_ARTIFACT_TYPE_EMPTY",
    "FOAE artifact type is required",
  );
  nonEmpty(
    claim.claimedProducerId,
    "FOAE_CLAIMED_PRODUCER_EMPTY",
    "FOAE claimed producer is required",
  );
  nonEmpty(
    claim.producerAuthorityRef,
    "FOAE_PRODUCER_AUTHORITY_REF_EMPTY",
    "FOAE producer authority reference is required",
  );
  nonEmpty(
    claim.originalArtifactHash,
    "FOAE_ARTIFACT_HASH_EMPTY",
    "FOAE original artifact hash is required",
  );
  nonEmpty(
    claim.artifactVersion,
    "FOAE_ARTIFACT_VERSION_EMPTY",
    "FOAE artifact version is required",
  );
  nonEmpty(claim.provenance, "FOAE_PROVENANCE_EMPTY", "FOAE provenance is required");
  nonEmpty(claim.validFrom, "FOAE_VALID_FROM_EMPTY", "FOAE validity start is required");

  validateTimestamp(
    claim.validFrom,
    "FOAE_VALID_FROM_INVALID",
    "FOAE validity start must be valid",
  );

  if (claim.validUntil !== undefined) {
    validateTimestamp(
      claim.validUntil,
      "FOAE_VALID_UNTIL_INVALID",
      "FOAE validity end must be valid",
    );

    invariant(
      claim.validUntil > claim.validFrom,
      "FOAE_VALIDITY_WINDOW_INVALID",
      "FOAE validity end must be after validity start",
    );
  }

  invariant(
    /^[a-f0-9]{64}$/i.test(claim.originalArtifactHash),
    "FOAE_ARTIFACT_HASH_INVALID",
    "FOAE artifact hash must be a SHA-256 hexadecimal digest",
  );

  for (const observation of claim.observations) {
    validateObservation(observation);
  }

  if (claim.producerAssurance !== undefined) {
    validateProducerAssurance(claim.producerAssurance);
  }
}

export function validateProducerOriginVerification(
  result: ProducerOriginVerificationResult,
): void {
  nonEmpty(result.claimId, "FOAE_RESULT_CLAIM_EMPTY", "FOAE result claim id is required");
  nonEmpty(
    result.artifactId,
    "FOAE_RESULT_ARTIFACT_EMPTY",
    "FOAE result artifact id is required",
  );
  nonEmpty(
    result.producerId,
    "FOAE_RESULT_PRODUCER_EMPTY",
    "FOAE result producer id is required",
  );
  nonEmpty(
    result.verifierId,
    "FOAE_RESULT_VERIFIER_EMPTY",
    "FOAE result verifier id is required",
  );
  nonEmpty(
    result.verifiedAt,
    "FOAE_RESULT_TIME_EMPTY",
    "FOAE result verification time is required",
  );
  nonEmpty(result.reason, "FOAE_RESULT_REASON_EMPTY", "FOAE result reason is required");
  nonEmpty(
    result.authenticatedVerificationEvidenceId,
    "FOAE_RESULT_AUTH_EVIDENCE_EMPTY",
    "Authenticated verification evidence id is required",
  );
  nonEmpty(
    result.producerAuthorityRef,
    "FOAE_RESULT_AUTHORITY_REF_EMPTY",
    "Producer authority reference is required",
  );
  nonEmpty(
    result.originalArtifactHash,
    "FOAE_RESULT_ARTIFACT_HASH_EMPTY",
    "Original artifact hash is required",
  );
  nonEmpty(result.resultHash, "FOAE_RESULT_HASH_EMPTY", "Result hash is required");

  validateTimestamp(
    result.verifiedAt,
    "FOAE_RESULT_TIME_INVALID",
    "FOAE result verification time must be valid",
  );

  invariant(
    /^[a-f0-9]{64}$/i.test(result.originalArtifactHash),
    "FOAE_RESULT_ARTIFACT_HASH_INVALID",
    "Original artifact hash must be a SHA-256 hexadecimal digest",
  );

  invariant(
    /^[a-f0-9]{64}$/i.test(result.resultHash),
    "FOAE_RESULT_HASH_INVALID",
    "FOAE result hash must be a SHA-256 hexadecimal digest",
  );
}

function claimPayload(claim: ProducerOriginClaim): ProducerOriginClaim {
  const payload: ProducerOriginClaim = {
    ...claim,
    observations: claim.observations.map((observation) => ({ ...observation })),
  };

  if (claim.producerAssurance !== undefined) {
    payload.producerAssurance = {
      ...claim.producerAssurance,
      limitations: [...claim.producerAssurance.limitations],
    };
  }

  return payload;
}

function verificationPayload(
  result: ProducerOriginVerificationResult,
): Omit<ProducerOriginVerificationResult, "resultHash"> {
  const { resultHash: _resultHash, ...payload } = result;
  return payload;
}

export function createProducerOriginResultHash(
  result: Omit<ProducerOriginVerificationResult, "resultHash">,
): string {
  return canonicalHash(result);
}

export function verifyProducerOriginResultIntegrity(
  result: ProducerOriginVerificationResult,
): boolean {
  try {
    validateProducerOriginVerification(result);
  } catch {
    return false;
  }

  return canonicalHash(verificationPayload(result)) === result.resultHash;
}

export function createProducerOriginEvidenceHash(
  evidence: Omit<ProducerOriginEvidence, "recordHash">,
): string {
  return canonicalHash(evidence);
}

export function verifyProducerOriginEvidenceIntegrity(
  evidence: ProducerOriginEvidence,
): boolean {
  try {
    validateProducerOriginClaim(evidence.claim);
    validateProducerOriginVerification(evidence.verification);

    invariant(
      evidence.verification.claimId === evidence.claim.id,
      "FOAE_RESULT_CLAIM_BINDING_INVALID",
      "Verification result must bind to its claim",
    );

    invariant(
      evidence.verification.artifactId === evidence.claim.artifactId,
      "FOAE_RESULT_ARTIFACT_BINDING_INVALID",
      "Verification result must bind to its artifact",
    );

    invariant(
      evidence.verification.producerId === evidence.claim.claimedProducerId,
      "FOAE_RESULT_PRODUCER_BINDING_INVALID",
      "Verification result must bind to the claimed producer",
    );

    invariant(
      evidence.verification.originalArtifactHash ===
        evidence.claim.originalArtifactHash,
      "FOAE_RESULT_HASH_BINDING_INVALID",
      "Verification result must bind to the original artifact hash",
    );
  } catch {
    return false;
  }

  return (
    createProducerOriginEvidenceHash({
      claim: claimPayload(evidence.claim),
      verification: { ...evidence.verification },
    }) === evidence.recordHash
  );
}
