import assert from "node:assert/strict";
import test from "node:test";

import {
  createProductionThresholdBoundary,
  validateProductionThresholdTrustAnchor,
  validateThresholdCeremony,
  type ProductionThresholdTrustAnchor,
  type ThresholdCeremonyRecord,
} from "../../src/security/threshold-production.js";
import {
  PRODUCTION_THRESHOLD_ALGORITHM,
  type ThresholdHsmProvider,
} from "../../src/security/threshold-signing.js";

const anchor: ProductionThresholdTrustAnchor = {
  keyId: "giia-production-threshold-root",
  algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
  quorum: 3,
  memberCount: 5,
  authoritySetFingerprint: "trusted-authority-fingerprint",
  publicKeyPem: "PRODUCTION_HSM_PUBLIC_KEY",
  ceremonyId: "ceremony-production-001",
  createdAt: "2026-10-06T00:00:00.000Z",
  production: true,
};

const ceremony: ThresholdCeremonyRecord = {
  ceremonyId: "ceremony-production-001",
  algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
  quorum: 3,
  memberCount: 5,
  keyId: "giia-production-threshold-root",
  authoritySetFingerprint: "trusted-authority-fingerprint",
  publicKeyPem: "PRODUCTION_HSM_PUBLIC_KEY",
  participants: [
    "authority-1",
    "authority-2",
    "authority-3",
    "authority-4",
    "authority-5",
  ],
  createdAt: "2026-10-06T00:00:00.000Z",
  completed: true,
};

test("P0-E production trust anchor is exactly 3-of-5", () => {
  validateProductionThresholdTrustAnchor(anchor);
  assert.equal(anchor.quorum, 3);
  assert.equal(anchor.memberCount, 5);
});

test("P0-E incomplete ceremony fails closed", () => {
  assert.throws(
    () =>
      validateThresholdCeremony({
        ...ceremony,
        completed: false,
      }),
    /P0_THRESHOLD_CEREMONY_INCOMPLETE/,
  );
});

test("P0-E ceremony must contain exactly five participants", () => {
  assert.throws(
    () =>
      validateThresholdCeremony({
        ...ceremony,
        participants: ["authority-1", "authority-2"],
      }),
    /P0_THRESHOLD_CEREMONY_PARTICIPANTS_INVALID/,
  );
});

test("P0-E production boundary refuses missing provider", () => {
  assert.throws(
    () =>
      createProductionThresholdBoundary(
        anchor,
        undefined,
      ),
    /P0_THRESHOLD_HSM_PROVIDER_REQUIRED/,
  );
});

test("P0-E request cannot substitute authority fingerprint", () => {
  const provider: ThresholdHsmProvider = {
    production: true,
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    async sign(request) {
      return {
        algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
        keyId: request.keyId,
        authoritySetFingerprint:
          request.authoritySetFingerprint,
        signatureBase64: "provider-signature",
      };
    },
  };

  const boundary = createProductionThresholdBoundary(
    anchor,
    provider,
  );

  assert.rejects(
    boundary.sign({
      signingDomain: "GIIA-DECISION",
      messageDigest: "digest",
      keyId: anchor.keyId,
      authoritySetFingerprint: "attacker-fingerprint",
    }),
    /P0_THRESHOLD_REQUEST_TRUST_ROOT_MISMATCH/,
  );
});

test("P0-E request cannot substitute production key", () => {
  const provider: ThresholdHsmProvider = {
    production: true,
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    async sign(request) {
      return {
        algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
        keyId: request.keyId,
        authoritySetFingerprint:
          request.authoritySetFingerprint,
        signatureBase64: "provider-signature",
      };
    },
  };

  const boundary = createProductionThresholdBoundary(
    anchor,
    provider,
  );

  assert.rejects(
    boundary.sign({
      signingDomain: "GIIA-DECISION",
      messageDigest: "digest",
      keyId: "attacker-key",
      authoritySetFingerprint:
        anchor.authoritySetFingerprint,
    }),
    /P0_THRESHOLD_REQUEST_KEY_MISMATCH/,
  );
});

test("P0-E valid provider remains behind production boundary", async () => {
  const provider: ThresholdHsmProvider = {
    production: true,
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    async sign(request) {
      return {
        algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
        keyId: request.keyId,
        authoritySetFingerprint:
          request.authoritySetFingerprint,
        signatureBase64: "provider-signature",
      };
    },
  };

  const boundary = createProductionThresholdBoundary(
    anchor,
    provider,
  );

  const result = await boundary.sign({
    signingDomain: "GIIA-DECISION",
    messageDigest: "digest",
    keyId: anchor.keyId,
    authoritySetFingerprint:
      anchor.authoritySetFingerprint,
  });

  assert.equal(
    result.algorithm,
    PRODUCTION_THRESHOLD_ALGORITHM,
  );
});
