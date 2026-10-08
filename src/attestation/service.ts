import type {
  ComponentAttestation,
  InstitutionalIntegrityResult,
} from "./types.js";

export interface AttestationVerificationContext {
  readonly expectedComponentId: string;
  readonly expectedComponentType: "GOVERNOR" | "GUARDIAN";
  readonly expectedImplementationVersion: string;
  readonly expectedMeasurement: string;
  readonly expectedEnvironmentBinding: string;
  readonly expectedPolicyVersion: string;
  readonly expectedConstitutionVersion: string;
  readonly nonce: string;
  readonly at: string;
}

function result(
  input: AttestationVerificationContext,
  status: InstitutionalIntegrityResult["status"],
  reason: string,
  attestation: ComponentAttestation | null = null,
): InstitutionalIntegrityResult {
  return {
    componentId: input.expectedComponentId,
    componentType: input.expectedComponentType,
    status,
    verified: status === "VERIFIED",
    reason,
    attestationId: attestation?.attestationId ?? null,
    measurement: attestation?.measurement.measurement ?? null,
    verifiedAt: input.at,
  };
}

/**
 * Independent institutional-integrity verification.
 *
 * This function deliberately does not ask the component being verified
 * whether it considers itself trustworthy.
 */
export function verifyInstitutionalIntegrity(
  attestation: ComponentAttestation | null | undefined,
  input: AttestationVerificationContext,
): InstitutionalIntegrityResult {
  if (!attestation) {
    return result(input, "MISSING", "ATTESTATION_MISSING");
  }

  if (attestation.componentId !== input.expectedComponentId) {
    return result(input, "INVALID", "ATTESTATION_COMPONENT_MISMATCH", attestation);
  }

  if (attestation.componentType !== input.expectedComponentType) {
    return result(input, "INVALID", "ATTESTATION_COMPONENT_TYPE_MISMATCH", attestation);
  }

  if (attestation.measurement.implementationVersion !== input.expectedImplementationVersion) {
    return result(input, "INVALID", "ATTESTATION_VERSION_MISMATCH", attestation);
  }

  if (attestation.measurement.measurement !== input.expectedMeasurement) {
    return result(input, "INVALID", "ATTESTATION_MEASUREMENT_MISMATCH", attestation);
  }

  if (attestation.measurement.environmentBinding !== input.expectedEnvironmentBinding) {
    return result(input, "INVALID", "ATTESTATION_ENVIRONMENT_MISMATCH", attestation);
  }

  if (attestation.measurement.policyVersion !== input.expectedPolicyVersion) {
    return result(input, "INVALID", "ATTESTATION_POLICY_MISMATCH", attestation);
  }

  if (attestation.measurement.constitutionVersion !== input.expectedConstitutionVersion) {
    return result(input, "INVALID", "ATTESTATION_CONSTITUTION_MISMATCH", attestation);
  }

  if (attestation.nonce !== input.nonce) {
    return result(input, "INVALID", "ATTESTATION_NONCE_MISMATCH", attestation);
  }

  if (!attestation.signatureValid) {
    return result(input, "INVALID", "ATTESTATION_SIGNATURE_INVALID", attestation);
  }

  if (attestation.revoked) {
    return result(input, "REVOKED", "ATTESTATION_REVOKED", attestation);
  }

  const now = Date.parse(input.at);
  const issued = Date.parse(attestation.issuedAt);
  const expires = Date.parse(attestation.expiresAt);

  if (
    !Number.isFinite(now) ||
    !Number.isFinite(issued) ||
    !Number.isFinite(expires)
  ) {
    return result(input, "INVALID", "ATTESTATION_TIME_INVALID", attestation);
  }

  if (now < issued) {
    return result(input, "INVALID", "ATTESTATION_NOT_YET_VALID", attestation);
  }

  if (now >= expires) {
    return result(input, "EXPIRED", "ATTESTATION_EXPIRED", attestation);
  }

  return result(input, "VERIFIED", "INSTITUTIONAL_INTEGRITY_VERIFIED", attestation);
}
