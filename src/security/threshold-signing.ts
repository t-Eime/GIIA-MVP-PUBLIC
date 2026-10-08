/**
 * P0-E: Cryptographic threshold/HSM signing boundary.
 *
 * IMPORTANT:
 * - This interface deliberately does NOT implement fake threshold cryptography.
 * - Production signing requires an external threshold/HSM provider.
 * - Software multisignature is NOT accepted as a production substitute.
 * - The provider must return a single independently verifiable signature
 *   produced by a genuine threshold signing ceremony/backend.
 */

export const PRODUCTION_THRESHOLD_ALGORITHM =
  "THRESHOLD-3-OF-5-HSM" as const;

export const THRESHOLD_QUORUM = 3 as const;
export const THRESHOLD_MEMBER_COUNT = 5 as const;

export interface ThresholdSigningRequest {
  readonly signingDomain: string;
  readonly messageDigest: string;
  readonly keyId: string;
  readonly authoritySetFingerprint: string;
}

export interface ThresholdSigningResult {
  readonly algorithm: typeof PRODUCTION_THRESHOLD_ALGORITHM;
  readonly keyId: string;
  readonly authoritySetFingerprint: string;
  readonly signatureBase64: string;
}

export interface ThresholdHsmProvider {
  readonly production: true;
  readonly algorithm: typeof PRODUCTION_THRESHOLD_ALGORITHM;

  sign(
    request: ThresholdSigningRequest,
  ): Promise<ThresholdSigningResult>;
}

/**
 * Production adapter.
 *
 * No fallback is permitted. A real HSM/MPC provider must be injected.
 */
export function createProductionThresholdSigner(
  provider: ThresholdHsmProvider | undefined,
): ThresholdHsmProvider {
  if (!provider) {
    throw new Error("P0_THRESHOLD_HSM_PROVIDER_REQUIRED");
  }

  if (provider.production !== true) {
    throw new Error("P0_THRESHOLD_PROVIDER_NOT_PRODUCTION");
  }

  if (provider.algorithm !== PRODUCTION_THRESHOLD_ALGORITHM) {
    throw new Error("P0_THRESHOLD_ALGORITHM_INVALID");
  }

  return Object.freeze({
    production: true as const,
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    sign: async (
      request: ThresholdSigningRequest,
    ): Promise<ThresholdSigningResult> => {
      if (!request.messageDigest) {
        throw new Error("P0_THRESHOLD_MESSAGE_DIGEST_REQUIRED");
      }

      if (!request.keyId) {
        throw new Error("P0_THRESHOLD_KEY_ID_REQUIRED");
      }

      if (!request.authoritySetFingerprint) {
        throw new Error("P0_THRESHOLD_AUTHORITY_FINGERPRINT_REQUIRED");
      }

      const result = await provider.sign(request);

      if (result.algorithm !== PRODUCTION_THRESHOLD_ALGORITHM) {
        throw new Error("P0_THRESHOLD_RESULT_ALGORITHM_INVALID");
      }

      if (result.keyId !== request.keyId) {
        throw new Error("P0_THRESHOLD_RESULT_KEY_MISMATCH");
      }

      if (
        result.authoritySetFingerprint !==
        request.authoritySetFingerprint
      ) {
        throw new Error("P0_THRESHOLD_RESULT_TRUST_ROOT_MISMATCH");
      }

      if (!result.signatureBase64) {
        throw new Error("P0_THRESHOLD_SIGNATURE_MISSING");
      }

      return Object.freeze(result);
    },
  });
}

/**
 * Explicitly non-production software implementation marker.
 *
 * This exists only so the architecture can distinguish development
 * signing from production threshold signing. It MUST NOT be accepted
 * by createProductionThresholdSigner().
 */
export interface DevelopmentOnlyThresholdSimulator {
  readonly production: false;
  readonly algorithm: "DEVELOPMENT-NON-THRESHOLD";
}

export const DEVELOPMENT_ONLY_THRESHOLD_SIMULATOR:
  DevelopmentOnlyThresholdSimulator = Object.freeze({
    production: false,
    algorithm: "DEVELOPMENT-NON-THRESHOLD" as const,
  });
