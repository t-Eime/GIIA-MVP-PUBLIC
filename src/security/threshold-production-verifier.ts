import {
  createProductionThresholdSigner,
  type ThresholdHsmProvider,
  type ThresholdSigningRequest,
  type ThresholdSigningResult,
} from "./threshold-signing.js";

import {
  verifyThresholdSignatureIndependently,
  type IndependentThresholdTrustAnchor,
  type IndependentThresholdVerification,
} from "./threshold-independent-verifier.js";

export interface ProductionThresholdSigningOutcome {
  readonly result: ThresholdSigningResult;
  readonly independentVerification: IndependentThresholdVerification;
}

export async function signAndIndependentlyVerifyThreshold(
  provider: ThresholdHsmProvider | undefined,
  trustAnchor: IndependentThresholdTrustAnchor,
  request: ThresholdSigningRequest,
): Promise<ProductionThresholdSigningOutcome> {
  const signer = createProductionThresholdSigner(provider);

  if (
    request.keyId !== trustAnchor.keyId ||
    request.authoritySetFingerprint !==
      trustAnchor.authoritySetFingerprint
  ) {
    throw new Error(
      "P0_THRESHOLD_TRUST_ANCHOR_REQUEST_MISMATCH",
    );
  }

  const result = await signer.sign(request);

  const independentVerification =
    verifyThresholdSignatureIndependently({
      request,
      result,
      trustAnchor,
    });

  if (!independentVerification.valid) {
    throw new Error(
      `P0_THRESHOLD_INDEPENDENT_VERIFICATION_FAILED:${independentVerification.reason}`,
    );
  }

  return Object.freeze({
    result,
    independentVerification,
  });
}
