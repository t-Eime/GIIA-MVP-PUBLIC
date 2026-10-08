import {
  createHash,
  verify as cryptoVerify,
} from "node:crypto";

import {
  PRODUCTION_THRESHOLD_ALGORITHM,
  THRESHOLD_MEMBER_COUNT,
  THRESHOLD_QUORUM,
  type ThresholdSigningRequest,
  type ThresholdSigningResult,
} from "./threshold-signing.js";

export interface IndependentThresholdTrustAnchor {
  readonly keyId: string;
  readonly algorithm: typeof PRODUCTION_THRESHOLD_ALGORITHM;
  readonly quorum: typeof THRESHOLD_QUORUM;
  readonly memberCount: typeof THRESHOLD_MEMBER_COUNT;
  readonly authoritySetFingerprint: string;
  readonly publicKeyPem: string;
  readonly ceremonyId: string;
  readonly createdAt: string;
  readonly production: true;
}

export interface IndependentThresholdVerificationInput {
  readonly request: ThresholdSigningRequest;
  readonly result: ThresholdSigningResult;
  readonly trustAnchor: IndependentThresholdTrustAnchor;
}

export interface IndependentThresholdVerification {
  readonly valid: boolean;
  readonly reason:
    | "VALID"
    | "TRUST_ANCHOR_INVALID"
    | "ALGORITHM_MISMATCH"
    | "KEY_BINDING_MISMATCH"
    | "AUTHORITY_SET_MISMATCH"
    | "QUORUM_INVALID"
    | "MEMBER_COUNT_INVALID"
    | "EMPTY_SIGNATURE"
    | "SIGNATURE_INVALID";
}

function digestBytes(value: string): Buffer {
  return Buffer.from(value, "utf8");
}

export function verifyThresholdSignatureIndependently(
  input: IndependentThresholdVerificationInput,
): IndependentThresholdVerification {
  const { request, result, trustAnchor } = input;

  if (
    trustAnchor.production !== true ||
    trustAnchor.algorithm !== PRODUCTION_THRESHOLD_ALGORITHM ||
    trustAnchor.quorum !== THRESHOLD_QUORUM ||
    trustAnchor.memberCount !== THRESHOLD_MEMBER_COUNT ||
    !trustAnchor.keyId ||
    !trustAnchor.authoritySetFingerprint ||
    !trustAnchor.publicKeyPem ||
    !trustAnchor.ceremonyId ||
    !trustAnchor.createdAt
  ) {
    return {
      valid: false,
      reason: "TRUST_ANCHOR_INVALID",
    };
  }

  if (request.signingDomain.length === 0 || request.messageDigest.length === 0) {
    return {
      valid: false,
      reason: "SIGNATURE_INVALID",
    };
  }

  if (result.algorithm !== trustAnchor.algorithm) {
    return {
      valid: false,
      reason: "ALGORITHM_MISMATCH",
    };
  }

  if (
    request.keyId !== trustAnchor.keyId ||
    result.keyId !== trustAnchor.keyId
  ) {
    return {
      valid: false,
      reason: "KEY_BINDING_MISMATCH",
    };
  }

  if (
    request.authoritySetFingerprint !==
      trustAnchor.authoritySetFingerprint ||
    result.authoritySetFingerprint !==
      trustAnchor.authoritySetFingerprint
  ) {
    return {
      valid: false,
      reason: "AUTHORITY_SET_MISMATCH",
    };
  }

  if (
    trustAnchor.quorum !== 3 ||
    trustAnchor.memberCount !== 5
  ) {
    return {
      valid: false,
      reason: "QUORUM_INVALID",
    };
  }

  if (
    !Number.isInteger(trustAnchor.memberCount) ||
    trustAnchor.memberCount !== 5
  ) {
    return {
      valid: false,
      reason: "MEMBER_COUNT_INVALID",
    };
  }

  if (!result.signatureBase64) {
    return {
      valid: false,
      reason: "EMPTY_SIGNATURE",
    };
  }

  let signature: Buffer;

  try {
    signature = Buffer.from(result.signatureBase64, "base64");
  } catch {
    return {
      valid: false,
      reason: "SIGNATURE_INVALID",
    };
  }

  if (signature.length === 0) {
    return {
      valid: false,
      reason: "EMPTY_SIGNATURE",
    };
  }

  /*
   * IMPORTANT:
   *
   * This verifier does not trust the provider to say that its
   * signature is valid.
   *
   * It independently verifies the returned signature against the
   * externally pinned public verification key.
   *
   * The production threshold provider MUST produce a signature
   * compatible with this verification algorithm before this path
   * can be activated.
   *
   * No Ed25519 software multisignature fallback is permitted here.
   */
  const message = digestBytes(
    createHash("sha256")
      .update(request.signingDomain, "utf8")
      .update("\0", "utf8")
      .update(request.messageDigest, "utf8")
      .digest("hex"),
  );

  let valid = false;

  try {
    valid = cryptoVerify(
      null,
      message,
      trustAnchor.publicKeyPem,
      signature,
    );
  } catch {
    valid = false;
  }

  return valid
    ? { valid: true, reason: "VALID" }
    : { valid: false, reason: "SIGNATURE_INVALID" };
}
