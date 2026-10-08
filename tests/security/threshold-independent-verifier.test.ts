import test from "node:test";
import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";

import {
  PRODUCTION_THRESHOLD_ALGORITHM,
} from "../../src/security/threshold-signing.js";

import {
  verifyThresholdSignatureIndependently,
} from "../../src/security/threshold-independent-verifier.js";

function fixture() {
  const { publicKey, privateKey } =
    generateKeyPairSync("ed25519");

  const publicKeyPem = publicKey.export({
    type: "spki",
    format: "pem",
  }).toString();

  const messageDigest =
    createHash("sha256")
      .update("test-message")
      .digest("hex");

  const request = {
    signingDomain: "GIIA.P0E.TEST",
    messageDigest,
    keyId: "real-threshold-key",
    authoritySetFingerprint: "authority-fingerprint",
  } as const;

  const message = Buffer.from(
    createHash("sha256")
      .update(request.signingDomain, "utf8")
      .update("\0", "utf8")
      .update(request.messageDigest, "utf8")
      .digest("hex"),
    "utf8",
  );

  const signatureBase64 =
    sign(null, message, privateKey).toString("base64");

  const trustAnchor = {
    keyId: "real-threshold-key",
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    quorum: 3 as const,
    memberCount: 5 as const,
    authoritySetFingerprint: "authority-fingerprint",
    publicKeyPem,
    ceremonyId: "ceremony-test",
    createdAt: new Date(0).toISOString(),
    production: true as const,
  };

  const result = {
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    keyId: "real-threshold-key",
    authoritySetFingerprint: "authority-fingerprint",
    signatureBase64,
  } as const;

  return {
    request,
    result,
    trustAnchor,
  };
}

test("P0-E independent verifier rejects wrong key binding", () => {
  const f = fixture();

  const result = verifyThresholdSignatureIndependently({
    request: f.request,
    result: {
      ...f.result,
      keyId: "attacker-key",
    },
    trustAnchor: f.trustAnchor,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "KEY_BINDING_MISMATCH");
});

test("P0-E independent verifier rejects authority substitution", () => {
  const f = fixture();

  const result = verifyThresholdSignatureIndependently({
    request: {
      ...f.request,
      authoritySetFingerprint: "attacker-authority-set",
    },
    result: f.result,
    trustAnchor: f.trustAnchor,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "AUTHORITY_SET_MISMATCH");
});

test("P0-E independent verifier rejects algorithm substitution", () => {
  const f = fixture();

  const result = verifyThresholdSignatureIndependently({
    request: f.request,
    result: {
      ...f.result,
      algorithm: "ED25519-MULTISIG-3-OF-5" as never,
    },
    trustAnchor: f.trustAnchor,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "ALGORITHM_MISMATCH");
});

test("P0-E independent verifier rejects signature mutation", () => {
  const f = fixture();

  const bytes = Buffer.from(
    f.result.signatureBase64,
    "base64",
  );

  assert.ok(bytes.length > 0);
  bytes[0] = (bytes[0] ?? 0) ^ 0xff;

  const result = verifyThresholdSignatureIndependently({
    request: f.request,
    result: {
      ...f.result,
      signatureBase64: bytes.toString("base64"),
    },
    trustAnchor: f.trustAnchor,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "SIGNATURE_INVALID");
});

test("P0-E independent verifier rejects invalid trust anchor", () => {
  const f = fixture();

  const result = verifyThresholdSignatureIndependently({
    request: f.request,
    result: f.result,
    trustAnchor: {
      ...f.trustAnchor,
      quorum: 2 as never,
    },
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "TRUST_ANCHOR_INVALID");
});

test("P0-E independent verifier does not trust provider metadata alone", () => {
  const f = fixture();

  const result = verifyThresholdSignatureIndependently({
    request: f.request,
    result: {
      ...f.result,
      signatureBase64: Buffer.from(
        "provider-claims-valid",
      ).toString("base64"),
    },
    trustAnchor: f.trustAnchor,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "SIGNATURE_INVALID");
});
