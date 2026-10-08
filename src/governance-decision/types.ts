export interface GovernanceDecisionPayload {
  readonly decisionId: string;
  readonly requestId: string;
  readonly decision: "ALLOW";
  readonly actorId: string;
  readonly passportId: string;
  readonly action: string;
  readonly target: string;
  readonly payloadHash: string;
  readonly constitutionVersion: string;
  readonly governanceContext: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly provenance: "giia-authoritative-pipeline";
  readonly signingAuthorityId: string;
  readonly governanceKeyId: string;
  readonly governanceAuthorizationId: string;
  readonly governanceAuthorizationFingerprint: string;
}

export interface SignedGovernanceDecision {
  readonly payload: GovernanceDecisionPayload;
  readonly signingAlgorithm: "Ed25519";
  readonly signatureBase64: string;
}

export interface GovernanceDecisionVerificationResult {
  readonly valid: boolean;
  readonly reason: string;
}
