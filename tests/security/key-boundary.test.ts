import { test } from "node:test";
import assert from "node:assert/strict";

import { createTrustKey } from "../../src/trust/service.js";
import { KeySecurityBoundary } from "../../src/security/key-boundary.js";
import { GIIAError } from "../../src/core/errors.js";

const NOW = "2026-01-01T00:00:00.000Z";
const LATER = "2026-01-01T00:00:01.000Z";

function expectError(
  fn: () => unknown,
  code: string,
): void {
  assert.throws(fn, (error: unknown) => {
    return error instanceof GIIAError && error.code === code;
  });
}

test("key boundary registers active private material in memory", () => {
  const generated = createTrustKey(
    "boundary-root",
    "root",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  boundary.register(
    generated.key,
    generated.privateKeyPem,
    NOW,
  );

  assert.equal(
    boundary.hasPrivateMaterial(generated.key.id),
    true,
  );

  assert.deepEqual(
    boundary.getPublicKey(generated.key.id),
    generated.key,
  );
});

test("key boundary signs only with the registered key purpose", () => {
  const generated = createTrustKey(
    "boundary-anchor",
    "anchor",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  boundary.register(
    generated.key,
    generated.privateKeyPem,
    NOW,
  );

  const payload = {
    action: "test",
    value: "authorized",
  };

  const signature = boundary.sign(
    generated.key.id,
    "anchor",
    payload,
    NOW,
  );

  assert.equal(typeof signature, "string");
  assert.ok(signature.length > 0);
});

test("wrong key purpose is rejected", () => {
  const generated = createTrustKey(
    "boundary-root-purpose",
    "root",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  boundary.register(
    generated.key,
    generated.privateKeyPem,
    NOW,
  );

  expectError(
    () =>
      boundary.sign(
        generated.key.id,
        "delegation",
        { action: "test" },
        NOW,
      ),
    "KEY_PURPOSE_MISMATCH",
  );
});

test("unknown key cannot sign", () => {
  const boundary = new KeySecurityBoundary();

  expectError(
    () =>
      boundary.sign(
        "unknown-key",
        "root",
        { action: "test" },
        NOW,
      ),
    "KEY_NOT_REGISTERED",
  );
});

test("revoked key cannot sign", () => {
  const generated = createTrustKey(
    "boundary-revoked",
    "root",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  boundary.register(
    generated.key,
    generated.privateKeyPem,
    NOW,
  );

  boundary.revoke(
    generated.key.id,
    LATER,
    "compromise confirmed",
  );

  expectError(
    () =>
      boundary.sign(
        generated.key.id,
        "root",
        { action: "test" },
        LATER,
      ),
    "KEY_NOT_ACTIVE",
  );
});

test("quarantined key cannot sign", () => {
  const generated = createTrustKey(
    "boundary-quarantine",
    "root",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  boundary.register(
    generated.key,
    generated.privateKeyPem,
    NOW,
  );

  boundary.quarantine(
    generated.key.id,
    LATER,
    "suspected compromise",
  );

  expectError(
    () =>
      boundary.sign(
        generated.key.id,
        "root",
        { action: "test" },
        LATER,
      ),
    "KEY_QUARANTINED",
  );
});

test("expired key cannot sign", () => {
  const generated = createTrustKey(
    "boundary-expired",
    "root",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  boundary.register(
    generated.key,
    generated.privateKeyPem,
    NOW,
  );

  boundary.retire(
    generated.key.id,
    LATER,
    "scheduled retirement",
  );

  expectError(
    () =>
      boundary.sign(
        generated.key.id,
        "root",
        { action: "test" },
        LATER,
      ),
    "KEY_NOT_ACTIVE",
  );
});

test("key lifecycle is auditable", () => {
  const generated = createTrustKey(
    "boundary-audit",
    "root",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  boundary.register(
    generated.key,
    generated.privateKeyPem,
    NOW,
  );

  boundary.sign(
    generated.key.id,
    "root",
    { action: "test" },
    NOW,
  );

  boundary.quarantine(
    generated.key.id,
    LATER,
    "suspected compromise",
  );

  const events = boundary.lifecycleEvents();

  assert.deepEqual(
    events.map((event) => event.event),
    [
      "REGISTERED",
      "USED_FOR_SIGNING",
      "QUARANTINED",
    ],
  );

  assert.equal(events[0]?.sequence, 1);
  assert.equal(events[1]?.sequence, 2);
  assert.equal(events[2]?.sequence, 3);
});

test("private/public key substitution is rejected", () => {
  const registered = createTrustKey(
    "boundary-binding-registered",
    "root",
    "test",
    NOW,
  );

  const substituted = createTrustKey(
    "boundary-binding-substituted",
    "root",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  expectError(
    () =>
      boundary.register(
        registered.key,
        substituted.privateKeyPem,
        NOW,
      ),
    "KEY_PRIVATE_PUBLIC_BINDING_INVALID",
  );
});

test("duplicate key registration is rejected", () => {
  const generated = createTrustKey(
    "boundary-duplicate",
    "root",
    "test",
    NOW,
  );

  const boundary = new KeySecurityBoundary();

  boundary.register(
    generated.key,
    generated.privateKeyPem,
    NOW,
  );

  expectError(
    () =>
      boundary.register(
        generated.key,
        generated.privateKeyPem,
        NOW,
      ),
    "KEY_ALREADY_REGISTERED",
  );
});
