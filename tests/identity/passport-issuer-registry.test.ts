import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  InMemoryPassportIssuerRegistry,
  type PassportIssuer,
} from "../../src/identity/passport-issuer-registry.js";

function issuer(
  overrides: Partial<PassportIssuer> = {},
): PassportIssuer {
  const keys = generateKeyPairSync("ed25519");

  return {
    issuerId: "issuer-001",
    publicKeyPem: keys.publicKey.export({
      type: "spki",
      format: "pem",
    }) as string,
    jurisdiction: "NG",
    purpose: "agent-passport-issuer",
    status: "active",
    notBefore: "2026-01-01T00:00:00.000Z",
    notAfter: "2027-01-01T00:00:00.000Z",
    provenance: "test",
    ...overrides,
  };
}

test("registered active issuer is trusted", () => {
  const registry = new InMemoryPassportIssuerRegistry();
  registry.register(issuer());

  assert.equal(
    registry.isTrusted(
      "issuer-001",
      "2026-09-29T10:30:00.000Z",
    ),
    true,
  );
});

test("unknown issuer is not trusted", () => {
  const registry = new InMemoryPassportIssuerRegistry();

  assert.equal(
    registry.isTrusted(
      "unknown",
      "2026-09-29T10:30:00.000Z",
    ),
    false,
  );
});

test("revoked issuer is not trusted", () => {
  const registry = new InMemoryPassportIssuerRegistry();

  registry.register(
    issuer({
      status: "revoked",
    }),
  );

  assert.equal(
    registry.isTrusted(
      "issuer-001",
      "2026-09-29T10:30:00.000Z",
    ),
    false,
  );
});

test("issuer outside validity window is not trusted", () => {
  const registry = new InMemoryPassportIssuerRegistry();

  registry.register(issuer());

  assert.equal(
    registry.isTrusted(
      "issuer-001",
      "2028-01-01T00:00:00.000Z",
    ),
    false,
  );
});

test("issuer state cannot silently change", () => {
  const registry = new InMemoryPassportIssuerRegistry();

  const first = issuer();
  const second = issuer({
    issuerId: first.issuerId,
  });

  registry.register(first);

  assert.throws(
    () => registry.register(second),
    /PASSPORT_ISSUER_STATE_MISMATCH/,
  );
});

test("same issuer can be registered idempotently", () => {
  const registry = new InMemoryPassportIssuerRegistry();
  const value = issuer();

  registry.register(value);
  registry.register(value);

  assert.equal(
    registry.isTrusted(
      value.issuerId,
      "2026-09-29T10:30:00.000Z",
    ),
    true,
  );
});
