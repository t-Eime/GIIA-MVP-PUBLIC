/**
 * P0-E production threshold signing integration boundary.
 *
 * This module deliberately refuses to implement threshold cryptography itself.
 * A genuine 3-of-5 MPC/HSM provider MUST be injected.
 *
 * No software multisignature, ordinary single-key signature, or development
 * provider may satisfy this production boundary.
 */

import {
  createProductionThresholdSigner,
  PRODUCTION_THRESHOLD_ALGORITHM,
  THRESHOLD_MEMBER_COUNT,
  THRESHOLD_QUORUM,
  type ThresholdHsmProvider,
  type ThresholdSigningRequest,
  type ThresholdSigningResult,
} from "./threshold-signing.js";

export interface ProductionThresholdTrustAnchor {
  readonly keyId: string;
  readonly algorithm: typeof PRODUCTION_THRESHOLD_ALGORITHM;
  readonly quorum: 3;
  readonly memberCount: 5;
  readonly authoritySetFingerprint: string;
  readonly publicKeyPem: string;
  readonly ceremonyId: string;
  readonly createdAt: string;
  readonly production: true;
}

export interface ThresholdCeremonyRecord {
  readonly ceremonyId: string;
  readonly algorithm: typeof PRODUCTION_THRESHOLD_ALGORITHM;
  readonly quorum: 3;
  readonly memberCount: 5;
  readonly keyId: string;
  readonly authoritySetFingerprint: string;
  readonly publicKeyPem: string;
  readonly participants: readonly string[];
  readonly createdAt: string;
  readonly completed: boolean;
}

export function validateProductionThresholdTrustAnchor(
  anchor: ProductionThresholdTrustAnchor,
): void {
  if (anchor.production !== true) {
    throw new Error("P0_THRESHOLD_ANCHOR_NOT_PRODUCTION");
  }

  if (anchor.algorithm !== PRODUCTION_THRESHOLD_ALGORITHM) {
    throw new Error("P0_THRESHOLD_ANCHOR_ALGORITHM_INVALID");
  }

  if (anchor.quorum !== THRESHOLD_QUORUM) {
    throw new Error("P0_THRESHOLD_ANCHOR_QUORUM_INVALID");
  }

  if (anchor.memberCount !== THRESHOLD_MEMBER_COUNT) {
    throw new Error("P0_THRESHOLD_ANCHOR_MEMBER_COUNT_INVALID");
  }

  if (!anchor.keyId) {
    throw new Error("P0_THRESHOLD_ANCHOR_KEY_ID_REQUIRED");
  }

  if (!anchor.authoritySetFingerprint) {
    throw new Error(
      "P0_THRESHOLD_ANCHOR_FINGERPRINT_REQUIRED",
    );
  }

  if (!anchor.publicKeyPem) {
    throw new Error(
      "P0_THRESHOLD_ANCHOR_PUBLIC_KEY_REQUIRED",
    );
  }

  if (!anchor.ceremonyId) {
    throw new Error(
      "P0_THRESHOLD_ANCHOR_CEREMONY_REQUIRED",
    );
  }

  if (!anchor.createdAt) {
    throw new Error(
      "P0_THRESHOLD_ANCHOR_TIMESTAMP_REQUIRED",
    );
  }
}

export function createProductionThresholdBoundary(
  anchor: ProductionThresholdTrustAnchor,
  provider: ThresholdHsmProvider | undefined,
): {
  readonly anchor: ProductionThresholdTrustAnchor;
  readonly sign: (
    request: ThresholdSigningRequest,
  ) => Promise<ThresholdSigningResult>;
} {
  validateProductionThresholdTrustAnchor(anchor);

  const signer = createProductionThresholdSigner(provider);

  return Object.freeze({
    anchor: Object.freeze({
      ...anchor,
    }),
    sign: async (
      request: ThresholdSigningRequest,
    ): Promise<ThresholdSigningResult> => {
      if (
        request.authoritySetFingerprint !==
        anchor.authoritySetFingerprint
      ) {
        throw new Error(
          "P0_THRESHOLD_REQUEST_TRUST_ROOT_MISMATCH",
        );
      }

      if (request.keyId !== anchor.keyId) {
        throw new Error(
          "P0_THRESHOLD_REQUEST_KEY_MISMATCH",
        );
      }

      return signer.sign(request);
    },
  });
}

export function validateThresholdCeremony(
  ceremony: ThresholdCeremonyRecord,
): void {
  if (!ceremony.completed) {
    throw new Error(
      "P0_THRESHOLD_CEREMONY_INCOMPLETE",
    );
  }

  if (ceremony.algorithm !== PRODUCTION_THRESHOLD_ALGORITHM) {
    throw new Error(
      "P0_THRESHOLD_CEREMONY_ALGORITHM_INVALID",
    );
  }

  if (ceremony.quorum !== THRESHOLD_QUORUM) {
    throw new Error(
      "P0_THRESHOLD_CEREMONY_QUORUM_INVALID",
    );
  }

  if (ceremony.memberCount !== THRESHOLD_MEMBER_COUNT) {
    throw new Error(
      "P0_THRESHOLD_CEREMONY_MEMBER_COUNT_INVALID",
    );
  }

  if (ceremony.participants.length !== THRESHOLD_MEMBER_COUNT) {
    throw new Error(
      "P0_THRESHOLD_CEREMONY_PARTICIPANTS_INVALID",
    );
  }

  if (!ceremony.publicKeyPem) {
    throw new Error(
      "P0_THRESHOLD_CEREMONY_PUBLIC_KEY_REQUIRED",
    );
  }
}
