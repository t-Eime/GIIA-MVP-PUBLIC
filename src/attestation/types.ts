export type AttestationStatus =
  | "VERIFIED"
  | "INVALID"
  | "STALE"
  | "EXPIRED"
  | "REVOKED"
  | "MISSING"
  | "UNKNOWN"
  | "CONFLICTING";

export interface ComponentMeasurement {
  readonly componentId: string;
  readonly componentType: "GOVERNOR" | "GUARDIAN";
  readonly implementationVersion: string;
  readonly measurement: string;
  readonly environmentBinding: string;
  readonly policyVersion: string;
  readonly constitutionVersion: string;
}

export interface ComponentAttestation {
  readonly attestationId: string;
  readonly componentId: string;
  readonly componentType: "GOVERNOR" | "GUARDIAN";
  readonly measurement: ComponentMeasurement;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly issuerId: string;
  readonly revoked: boolean;
  readonly signatureValid: boolean;
}

export interface InstitutionalIntegrityResult {
  readonly componentId: string;
  readonly componentType: "GOVERNOR" | "GUARDIAN";
  readonly status: AttestationStatus;
  readonly verified: boolean;
  readonly reason: string;
  readonly attestationId: string | null;
  readonly measurement: string | null;
  readonly verifiedAt: string;
}
