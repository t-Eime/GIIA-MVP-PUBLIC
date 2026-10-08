export type FOAEArtifactType =
  | "certificate"
  | "declaration"
  | "standard"
  | "product"
  | "service"
  | "software"
  | "hardware"
  | "device"
  | "ai-system"
  | "machine"
  | "robot"
  | "vehicle"
  | "other";

export type FOAEVerificationStatus =
  | "VERIFIED"
  | "FAILED"
  | "EXPIRED"
  | "REVOKED"
  | "CONTRADICTED"
  | "UNVERIFIABLE";

export type FOAEObservationKind =
  | "CLAIM"
  | "OBSERVATION"
  | "EVIDENCE"
  | "VERIFICATION_RESULT";

export interface FOAEObservation {
  id: string;
  kind: FOAEObservationKind;
  statement: string;
  source: string;
  evidenceRef?: string;
  observedAt: string;
  provenance: string;
}

export interface ProducerAssurance {
  declaredBy: string;
  declarationRef: string;
  scope: string;
  terms: string;
  limitations: string[];
  effectiveFrom: string;
  effectiveUntil?: string;
  provenance: string;
}

export interface ProducerOriginClaim {
  id: string;
  organizationId: string;
  artifactId: string;
  artifactType: FOAEArtifactType;
  claimedProducerId: string;
  producerAuthorityRef: string;
  originalArtifactHash: string;
  artifactVersion: string;
  validFrom: string;
  validUntil?: string;
  revocationRef?: string;
  producerAssurance?: ProducerAssurance;
  observations: FOAEObservation[];
  provenance: string;
}

export interface ProducerOriginVerificationResult {
  claimId: string;
  artifactId: string;
  producerId: string;
  verifierId: string;
  verifiedAt: string;
  status: FOAEVerificationStatus;
  reason: string;
  authenticatedVerificationEvidenceId: string;
  evidenceChainFinalHash?: string;
  producerAuthorityRef: string;
  originalArtifactHash: string;
  resultHash: string;
}

export interface ProducerOriginEvidence {
  claim: ProducerOriginClaim;
  verification: ProducerOriginVerificationResult;
  recordHash: string;
}
