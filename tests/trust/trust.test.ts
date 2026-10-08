import { GIIAError } from "../../src/core/errors.js";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createAnchorWithSecureKey,
  createCredentialWithSecureKey,
  createDelegationWithSecureKey,
  createRoot,
  createTrustKey,
  verifyAnchor,
  verifyCredential,
  verifyDelegation,
  verifyTrustChain,
  rotateTrustKey,
} from "../../src/trust/service.js";
import { TrustRegistry } from "../../src/trust/registry.js";
import { KeySecurityBoundary } from "../../src/security/key-boundary.js";

const NOW = "2026-01-01T00:00:00.000Z";

function fixture() {
  const rootGenerated = createTrustKey(
    "root-key",
    "root",
    "test",
    NOW,
  );

  const anchorGenerated = createTrustKey(
    "anchor-key",
    "anchor",
    "test",
    NOW,
  );

  const delegationGenerated = createTrustKey(
    "delegation-key",
    "delegation",
    "test",
    NOW,
  );

  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();

  rootBoundary.register(
    rootGenerated.key,
    rootGenerated.privateKeyPem,
    NOW,
  );

  anchorBoundary.register(
    anchorGenerated.key,
    anchorGenerated.privateKeyPem,
    NOW,
  );

  delegationBoundary.register(
    delegationGenerated.key,
    delegationGenerated.privateKeyPem,
    NOW,
  );

  const root = createRoot(
    "root-1",
    "root-subject",
    rootGenerated.key.id,
    NOW,
    "test",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: "anchor-1",
      subject: "anchor-subject",
      rootId: root.id,
      signingKeyId: rootGenerated.key.id,
      constraints: ["issue:credential"],
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: rootBoundary,
      keyId: rootGenerated.key.id,
      purpose: "root",
      at: NOW,
    },
  );

  const delegation = createDelegationWithSecureKey(
    {
      id: "delegation-1",
      issuerAnchorId: anchor.id,
      delegateeId: "delegatee-1",
      signingKeyId: anchorGenerated.key.id,
      constraints: ["credential:issue"],
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: anchorBoundary,
      keyId: anchorGenerated.key.id,
      purpose: "anchor",
      at: NOW,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: "credential-1",
      subject: "delegatee-1",
      issuerDelegationId: delegation.id,
      claims: {
        capability: "credential:issue",
      },
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: delegationBoundary,
      keyId: delegationGenerated.key.id,
      purpose: "delegation",
      at: NOW,
    },
  );

  return {
    rootGenerated,
    anchorGenerated,
    delegationGenerated,
    root,
    anchor,
    delegation,
    credential,
  };
}

test("valid trust chain verifies", () => {
  const f = fixture();

  const result = verifyTrustChain({
    root: f.root,
    rootKey: f.rootGenerated.key,
    anchor: f.anchor,
    anchorKey: f.anchorGenerated.key,
    delegation: f.delegation,
    delegationKey: f.delegationGenerated.key,
    credential: f.credential,
    at: NOW,
  });

  assert.equal(result.valid, true);
  assert.equal(result.reason, "TRUST_CHAIN_VALID");
  assert.deepEqual(result.chain, [
    "root-1",
    "anchor-1",
    "delegation-1",
    "credential-1",
  ]);
});

test("secure signing boundary constructs and verifies complete trust chain", () => {
  const rootGenerated = createTrustKey(
    "secure-root-key",
    "root",
    "test",
    NOW,
  );

  const anchorGenerated = createTrustKey(
    "secure-anchor-key",
    "anchor",
    "test",
    NOW,
  );

  const delegationGenerated = createTrustKey(
    "secure-delegation-key",
    "delegation",
    "test",
    NOW,
  );

  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();

  rootBoundary.register(
    rootGenerated.key,
    rootGenerated.privateKeyPem,
    NOW,
  );

  anchorBoundary.register(
    anchorGenerated.key,
    anchorGenerated.privateKeyPem,
    NOW,
  );

  delegationBoundary.register(
    delegationGenerated.key,
    delegationGenerated.privateKeyPem,
    NOW,
  );

  const root = createRoot(
    "secure-root-1",
    "secure-root-subject",
    rootGenerated.key.id,
    NOW,
    "test",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: "secure-anchor-1",
      subject: "secure-anchor-subject",
      rootId: root.id,
      signingKeyId: rootGenerated.key.id,
      constraints: ["issue:credential"],
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: rootBoundary,
      keyId: rootGenerated.key.id,
      purpose: "root",
      at: NOW,
    },
  );

  const delegation = createDelegationWithSecureKey(
    {
      id: "secure-delegation-1",
      issuerAnchorId: anchor.id,
      delegateeId: "secure-delegatee-1",
      signingKeyId: anchorGenerated.key.id,
      constraints: ["credential:issue"],
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: anchorBoundary,
      keyId: anchorGenerated.key.id,
      purpose: "anchor",
      at: NOW,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: "secure-credential-1",
      subject: "secure-delegatee-1",
      issuerDelegationId: delegation.id,
      claims: {
        capability: "credential:issue",
      },
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: delegationBoundary,
      keyId: delegationGenerated.key.id,
      purpose: "delegation",
      at: NOW,
    },
  );

  const result = verifyTrustChain({
    root,
    rootKey: rootGenerated.key,
    anchor,
    anchorKey: anchorGenerated.key,
    delegation,
    delegationKey: delegationGenerated.key,
    credential,
    at: NOW,
  });

  assert.equal(result.valid, true);
  assert.equal(result.reason, "TRUST_CHAIN_VALID");

  assert.deepEqual(
    rootBoundary.lifecycleEvents().map((event) => event.event),
    ["REGISTERED", "USED_FOR_SIGNING"],
  );

  assert.deepEqual(
    anchorBoundary.lifecycleEvents().map((event) => event.event),
    ["REGISTERED", "USED_FOR_SIGNING"],
  );

  assert.deepEqual(
    delegationBoundary.lifecycleEvents().map((event) => event.event),
    ["REGISTERED", "USED_FOR_SIGNING"],
  );
});


test("secure signer purpose mismatch is rejected", () => {
  const generated = createTrustKey(
    "purpose-mismatch-key",
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

  const root = createRoot(
    "purpose-root-1",
    "purpose-root-subject",
    generated.key.id,
    NOW,
    "test",
  );

  assert.throws(
    () =>
      createAnchorWithSecureKey(
        {
          id: "purpose-anchor-1",
          subject: "purpose-anchor-subject",
          rootId: root.id,
          signingKeyId: "unused-anchor-key",
          constraints: ["issue:credential"],
          issuedAt: NOW,
          status: "active",
          provenance: "test",
        },
        {
          boundary,
          keyId: generated.key.id,
          purpose: "anchor",
          at: NOW,
        },
      ),
    (error: unknown) =>
      error instanceof GIIAError &&
      error.code === "SECURE_SIGNER_PURPOSE_MISMATCH",
  );
});

test("forged anchor signature is rejected", () => {
  const f = fixture();

  const forged = {
    ...f.anchor,
    subject: "attacker",
  };

  const result = verifyAnchor(
    forged,
    f.rootGenerated.key,
    NOW,
  );

  assert.equal(result, false);
});

test("anchor root substitution is rejected", () => {
  const f = fixture();

  const forged = {
    ...f.anchor,
    rootId: "different-root",
  };

  const result = verifyTrustChain({
    root: f.root,
    rootKey: f.rootGenerated.key,
    anchor: forged,
    anchorKey: f.anchorGenerated.key,
    delegation: f.delegation,
    delegationKey: f.delegationGenerated.key,
    credential: f.credential,
    at: NOW,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "ANCHOR_ROOT_BINDING_INVALID");
});

test("wrong root public key rejects anchor", () => {
  const f = fixture();
  const wrong = createTrustKey(
    "wrong-root",
    "root",
    "test",
    NOW,
  );

  assert.equal(
    verifyAnchor(f.anchor, wrong.key, NOW),
    false,
  );
});

test("anchor signing-key substitution inside signed anchor is rejected", () => {
  const f = fixture();

  const forged = {
    ...f.anchor,
    signingKeyId: "wrong-anchor-key",
  };

  const result = verifyTrustChain({
    root: f.root,
    rootKey: f.rootGenerated.key,
    anchor: forged,
    anchorKey: f.anchorGenerated.key,
    delegation: f.delegation,
    delegationKey: f.delegationGenerated.key,
    credential: f.credential,
    at: NOW,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "ANCHOR_SIGNATURE_INVALID");
});

test("delegation signature forgery is rejected", () => {
  const f = fixture();

  const forged = {
    ...f.delegation,
    delegateeId: "attacker",
  };

  assert.equal(
    verifyDelegation(
      forged,
      f.anchor,
      f.anchorGenerated.key,
      NOW,
    ),
    false,
  );
});

test("delegation issuer substitution is rejected", () => {
  const f = fixture();

  const forged = {
    ...f.delegation,
    issuerAnchorId: "different-anchor",
  };

  const result = verifyTrustChain({
    root: f.root,
    rootKey: f.rootGenerated.key,
    anchor: f.anchor,
    anchorKey: f.anchorGenerated.key,
    delegation: forged,
    delegationKey: f.delegationGenerated.key,
    credential: f.credential,
    at: NOW,
  });

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "DELEGATION_ISSUER_BINDING_INVALID",
  );
});

test("delegation signing-key substitution inside signed delegation is rejected", () => {
  const f = fixture();

  const forged = {
    ...f.delegation,
    signingKeyId: "wrong-delegation-key",
  };

  const result = verifyTrustChain({
    root: f.root,
    rootKey: f.rootGenerated.key,
    anchor: f.anchor,
    anchorKey: f.anchorGenerated.key,
    delegation: forged,
    delegationKey: f.delegationGenerated.key,
    credential: f.credential,
    at: NOW,
  });

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "DELEGATION_SIGNATURE_INVALID",
  );
});

test("credential signature forgery is rejected", () => {
  const f = fixture();

  const forged = {
    ...f.credential,
    subject: "attacker",
  };

  assert.equal(
    verifyCredential(
      forged,
      f.delegation,
      f.delegationGenerated.key,
      NOW,
    ),
    false,
  );
});

test("credential issuer substitution is rejected", () => {
  const f = fixture();

  const forged = {
    ...f.credential,
    issuerDelegationId: "different-delegation",
  };

  const result = verifyTrustChain({
    root: f.root,
    rootKey: f.rootGenerated.key,
    anchor: f.anchor,
    anchorKey: f.anchorGenerated.key,
    delegation: f.delegation,
    delegationKey: f.delegationGenerated.key,
    credential: forged,
    at: NOW,
  });

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "CREDENTIAL_ISSUER_BINDING_INVALID",
  );
});

test("expired anchor is rejected", () => {
  const f = fixture();

  const expired = {
    ...f.anchor,
    expiresAt: NOW,
  };

  const later = "2026-01-01T00:00:01.000Z";

  assert.equal(
    verifyDelegation(
      f.delegation,
      expired,
      f.anchorGenerated.key,
      later,
    ),
    false,
  );
});

test("revoked key is rejected", () => {
  const f = fixture();

  f.rootGenerated.key.status = "revoked";

  const result = verifyTrustChain({
    root: f.root,
    rootKey: f.rootGenerated.key,
    anchor: f.anchor,
    anchorKey: f.anchorGenerated.key,
    delegation: f.delegation,
    delegationKey: f.delegationGenerated.key,
    credential: f.credential,
    at: NOW,
  });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "ANCHOR_SIGNATURE_INVALID");
});

test("key rotation expires old key", () => {
  const original = createTrustKey(
    "old-key",
    "root",
    "test",
    NOW,
  );

  const rotated = rotateTrustKey(
    original.key,
    "new-key",
    "2026-02-01T00:00:00.000Z",
    "test",
  );

  assert.equal(original.key.status, "expired");
  assert.equal(
    original.key.notAfter,
    "2026-02-01T00:00:00.000Z",
  );
  assert.equal(rotated.key.status, "active");
  assert.equal(rotated.key.id, "new-key");
});

test("durable trust registry stores and retrieves trust objects", () => {
  const f = fixture();
  const registry = new TrustRegistry();

  registry.putKey(f.rootGenerated.key);
  registry.putRoot(f.root);
  registry.putAnchor(f.anchor);
  registry.putKey(f.anchorGenerated.key);
  registry.putDelegation(f.delegation);
  registry.putKey(f.delegationGenerated.key);
  registry.putCredential(f.credential);

  assert.deepEqual(
    registry.getKey(f.rootGenerated.key.id),
    f.rootGenerated.key,
  );
  assert.deepEqual(registry.getRoot(f.root.id), f.root);
  assert.deepEqual(registry.getAnchor(f.anchor.id), f.anchor);
  assert.deepEqual(
    registry.getDelegation(f.delegation.id),
    f.delegation,
  );
  assert.deepEqual(
    registry.getCredential(f.credential.id),
    f.credential,
  );

  registry.close();
});

test("trust revocation is durable", () => {
  const registry = new TrustRegistry();

  registry.revoke({
    objectType: "credential",
    objectId: "credential-1",
    revokedAt: NOW,
    reason: "compromised",
    authority: "authority-1",
    provenance: "test",
  });

  assert.equal(
    registry.isRevoked("credential", "credential-1"),
    true,
  );

  registry.close();
});

test("trust replay protection consumes request only once", () => {
  const registry = new TrustRegistry();

  assert.equal(
    registry.consumeReplay("request-1", NOW),
    true,
  );

  assert.equal(
    registry.consumeReplay(
      "request-1",
      "2026-01-01T00:00:01.000Z",
    ),
    false,
  );

  registry.close();
});

test("revoked secure signer is rejected", () => {
  const generated = createTrustKey(
    "revoked-secure-key",
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
    NOW,
    "compromise",
  );

  const root = createRoot(
    "revoked-root-1",
    "revoked-root-subject",
    generated.key.id,
    NOW,
    "test",
  );

  assert.throws(
    () =>
      createAnchorWithSecureKey(
        {
          id: "revoked-anchor-1",
          subject: "revoked-anchor-subject",
          rootId: root.id,
          signingKeyId: "revoked-anchor-key",
          constraints: ["issue:credential"],
          issuedAt: NOW,
          status: "active",
          provenance: "test",
        },
        {
          boundary,
          keyId: generated.key.id,
          purpose: "root",
          at: NOW,
        },
      ),
    (error: unknown) =>
      error instanceof GIIAError &&
      error.code === "KEY_NOT_ACTIVE",
  );
});

test("quarantined secure signer is rejected", () => {
  const generated = createTrustKey(
    "quarantined-secure-key",
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
    NOW,
    "suspicious activity",
  );

  const root = createRoot(
    "quarantined-root-1",
    "quarantined-root-subject",
    generated.key.id,
    NOW,
    "test",
  );

  assert.throws(
    () =>
      createAnchorWithSecureKey(
        {
          id: "quarantined-anchor-1",
          subject: "quarantined-anchor-subject",
          rootId: root.id,
          signingKeyId: "quarantined-anchor-key",
          constraints: ["issue:credential"],
          issuedAt: NOW,
          status: "active",
          provenance: "test",
        },
        {
          boundary,
          keyId: generated.key.id,
          purpose: "root",
          at: NOW,
        },
      ),
    (error: unknown) =>
      error instanceof GIIAError &&
      error.code === "KEY_QUARANTINED",
  );
});

test("expired secure signer is rejected", () => {
  const generated = createTrustKey(
    "expired-secure-key",
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
    NOW,
    "retired",
  );

  const root = createRoot(
    "expired-root-1",
    "expired-root-subject",
    generated.key.id,
    NOW,
    "test",
  );

  assert.throws(
    () =>
      createAnchorWithSecureKey(
        {
          id: "expired-anchor-1",
          subject: "expired-anchor-subject",
          rootId: root.id,
          signingKeyId: "expired-anchor-key",
          constraints: ["issue:credential"],
          issuedAt: NOW,
          status: "active",
          provenance: "test",
        },
        {
          boundary,
          keyId: generated.key.id,
          purpose: "root",
          at: NOW,
        },
      ),
    (error: unknown) =>
      error instanceof GIIAError &&
      error.code === "KEY_NOT_ACTIVE",
  );
});

test("secure signer cannot use an unregistered key ID", () => {
  const generated = createTrustKey(
    "registered-secure-key",
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

  const root = createRoot(
    "unregistered-root-1",
    "unregistered-root-subject",
    generated.key.id,
    NOW,
    "test",
  );

  assert.throws(
    () =>
      createAnchorWithSecureKey(
        {
          id: "unregistered-anchor-1",
          subject: "unregistered-anchor-subject",
          rootId: root.id,
          signingKeyId: "unregistered-anchor-key",
          constraints: ["issue:credential"],
          issuedAt: NOW,
          status: "active",
          provenance: "test",
        },
        {
          boundary,
          keyId: "never-registered-key",
          purpose: "root",
          at: NOW,
        },
      ),
    (error: unknown) =>
      error instanceof GIIAError &&
      error.code === "KEY_NOT_REGISTERED",
  );
});

test("secure signer cannot use a registered key with the wrong purpose", () => {
  const generated = createTrustKey(
    "wrong-purpose-secure-key",
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

  const root = createRoot(
    "wrong-purpose-root-1",
    "wrong-purpose-root-subject",
    generated.key.id,
    NOW,
    "test",
  );

  assert.throws(
    () =>
      createAnchorWithSecureKey(
        {
          id: "wrong-purpose-anchor-1",
          subject: "wrong-purpose-anchor-subject",
          rootId: root.id,
          signingKeyId: "wrong-purpose-anchor-key",
          constraints: ["issue:credential"],
          issuedAt: NOW,
          status: "active",
          provenance: "test",
        },
        {
          boundary,
          keyId: generated.key.id,
          purpose: "root",
          at: NOW,
        },
      ),
    (error: unknown) =>
      error instanceof GIIAError &&
      error.code === "KEY_PURPOSE_MISMATCH",
  );
});
