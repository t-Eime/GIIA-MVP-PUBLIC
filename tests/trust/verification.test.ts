import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createAnchorWithSecureKey,
  createCredentialWithSecureKey,
  createDelegationWithSecureKey,
  createRoot,
  createTrustKey,
  type TrustChainInput,
} from "../../src/trust/service.js";

import {
  createAuthenticatedVerification,
  verifyAuthenticatedVerificationEvidence,
} from "../../src/trust/verification.js";

import {
  authenticateVerifier,
  verifyAuthenticatedVerifier,
  VERIFIER_AUTHORITY_CLAIM,
  VERIFIER_AUTHORITY_HASH_CLAIM,
} from "../../src/trust/verifier.js";

import { KeySecurityBoundary } from "../../src/security/key-boundary.js";
import { canonicalize } from "../../src/core/canonical.js";
import { sha256 } from "../../src/core/security.js";
import type { Identity } from "../../src/identity/types.js";
import type { Authority } from "../../src/authority/types.js";
import type { AuthorizationRequest } from "../../src/authorization/types.js";

const NOW = "2026-01-01T00:00:00.000Z";
const LATER = "2026-01-02T00:00:00.000Z";
const VERIFY_RESOURCE = "trust-subject";

function createAuthority(
  identityId: string,
  id = "verifier-authority",
): Authority {
  return {
    id,
    holderIdentityId: identityId,
    trustCredentialId: "verifier-credential",
    scope: ["VERIFY:trust-subject"],
    issuedAt: NOW,
    status: "active",
    issuer: "test-issuer",
    provenance: "test",
  };
}

function createIdentity(
  id: string,
  kind: Identity["kind"] = "service",
): Identity {
  return {
    id,
    kind,
    status: "active",
    provenance: "test",
    createdAt: NOW,
  };
}

function createAuthorization(
  identityId: string,
  authorityId: string,
): AuthorizationRequest {
  return {
    id: `authorization-${identityId}`,
    subjectIdentityId: identityId,
    authorityId,
    action: "VERIFY",
    resource: VERIFY_RESOURCE,
    requestedAt: NOW,
  };
}

function createChain(
  subjectId: string,
  prefix: string,
  claims: Record<string, string> = {},
): TrustChainInput {
  const rootGenerated = createTrustKey(
    `${prefix}-root-key`,
    "root",
    "test",
    NOW,
  );

  const anchorGenerated = createTrustKey(
    `${prefix}-anchor-key`,
    "anchor",
    "test",
    NOW,
  );

  const delegationGenerated = createTrustKey(
    `${prefix}-delegation-key`,
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
    `${prefix}-root`,
    `${prefix}-root-subject`,
    rootGenerated.key.id,
    NOW,
    "test",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: `${prefix}-anchor`,
      subject: `${prefix}-anchor-subject`,
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
      id: `${prefix}-delegation`,
      issuerAnchorId: anchor.id,
      delegateeId: subjectId,
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
      id: `${prefix}-credential`,
      subject: subjectId,
      issuerDelegationId: delegation.id,
      claims,
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
    root,
    rootKey: rootGenerated.key,
    anchor,
    anchorKey: anchorGenerated.key,
    delegation,
    delegationKey: delegationGenerated.key,
    credential,
    at: NOW,
  };
}

function verifierFixture() {
  const identity = createIdentity("verifier-1");
  const authority = createAuthority(identity.id);

  const authorityHash = requireAuthorityHash(authority);

  const chain = createChain(
    identity.id,
    "verifier",
    {
      [VERIFIER_AUTHORITY_CLAIM]: authority.id,
      [VERIFIER_AUTHORITY_HASH_CLAIM]: authorityHash,
    },
  );

  const authorizationRequest = createAuthorization(
    identity.id,
    authority.id,
  );

  const verifier = authenticateVerifier({
    identity,
    authority,
    chain,
    authorizationRequest,
  });

  return {
    identity,
    authority,
    chain,
    authorizationRequest,
    verifier,
  };
}

function requireAuthorityHash(authority: Authority): string {
  return sha256(canonicalize(authority));
}

function subjectFixture() {
  return createChain(
    "verified-subject",
    "subject",
  );
}

test("authenticated verifier requires a valid identity/trust-chain binding", () => {
  const f = verifierFixture();

  assert.equal(f.verifier.verifierId, "verifier-1");
  assert.equal(
    f.verifier.identity.id,
    "verifier-1",
  );

  assert.equal(
    verifyAuthenticatedVerifier(f.verifier, NOW),
    true,
  );
});

test("fake verifier identity is rejected", () => {
  const f = verifierFixture();

  assert.throws(
    () =>
      authenticateVerifier({
        ...f,
        identity: {
          ...f.identity,
          id: "attacker",
        },
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "VERIFIER_IDENTITY_CHAIN_MISMATCH",
  );
});

test("verifier authority must belong to authenticated identity", () => {
  const f = verifierFixture();

  assert.throws(
    () =>
      authenticateVerifier({
        ...f,
        authority: {
          ...f.authority,
          holderIdentityId: "attacker",
        },
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "VERIFIER_AUTHORITY_HOLDER_MISMATCH",
  );
});

test("verifier authorization must belong to the authenticated identity", () => {
  const f = verifierFixture();

  assert.throws(
    () =>
      authenticateVerifier({
        ...f,
        authorizationRequest: {
          ...f.authorizationRequest,
          subjectIdentityId: "attacker",
        },
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "VERIFIER_AUTHORIZATION_SUBJECT_MISMATCH",
  );
});

test("verifier must actually be authorized for VERIFY", () => {
  const f = verifierFixture();

  assert.throws(
    () =>
      authenticateVerifier({
        ...f,
        authorizationRequest: {
          ...f.authorizationRequest,
          action: "DELETE",
        },
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "VERIFIER_NOT_AUTHORIZED",
  );
});

test("substituted authority contents are rejected", () => {
  const f = verifierFixture();

  assert.throws(
    () =>
      authenticateVerifier({
        ...f,
        authority: {
          ...f.authority,
          scope: ["VERIFY:other-resource"],
        },
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "VERIFIER_AUTHORITY_HASH_MISMATCH",
  );
});

test("forged verifier credential claims are rejected", () => {
  const f = verifierFixture();

  f.chain.credential.claims[VERIFIER_AUTHORITY_CLAIM] =
    "attacker-authority";

  assert.throws(
    () =>
      authenticateVerifier({
        ...f,
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "VERIFIER_TRUST_CHAIN_INVALID",
  );
});

test("altered authenticated verifier evidence is rejected", () => {
  const f = verifierFixture();

  const forged = {
    ...f.verifier,
    verifierId: "attacker",
  };

  assert.equal(
    verifyAuthenticatedVerifier(forged, NOW),
    false,
  );
});

test("replayed verifier authentication at another time is rejected", () => {
  const f = verifierFixture();

  assert.equal(
    verifyAuthenticatedVerifier(f.verifier, LATER),
    false,
  );
});

test("authenticated verification binds the verifier identity", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-1",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  assert.equal(evidence.verifierId, "verifier-1");
  assert.equal(
    evidence.verifierAuthenticationHash,
    verifier.verifier.authenticationHash,
  );
  assert.equal(
    evidence.trustResult.valid,
    true,
  );

  assert.equal(
    verifyAuthenticatedVerificationEvidence(
      evidence,
      "verified-subject",
      NOW,
    ),
    true,
  );
});

test("wrong verification subject is rejected", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  assert.throws(
    () =>
      createAuthenticatedVerification({
        id: "verification-2",
        subjectId: "attacker",
        verifier: verifier.verifier,
        verifiedAt: NOW,
        chain: subject,
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "VERIFICATION_SUBJECT_BINDING_INVALID",
  );
});

test("forged verifier authentication evidence cannot create verification evidence", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const forgedVerifier = {
    ...verifier.verifier,
    verifierId: "attacker",
  };

  assert.throws(
    () =>
      createAuthenticatedVerification({
        id: "verification-3",
        subjectId: "verified-subject",
        verifier: forgedVerifier,
        verifiedAt: NOW,
        chain: subject,
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "VERIFIER_AUTHENTICATION_INVALID",
  );
});

test("tampered verification evidence is rejected", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-4",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  const forged = {
    ...evidence,
    verifierId: "attacker-verifier",
  };

  assert.equal(
    verifyAuthenticatedVerificationEvidence(
      forged,
      "verified-subject",
      NOW,
    ),
    false,
  );
});

test("tampered trust result is rejected", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-5",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  const forged = {
    ...evidence,
    trustResult: {
      ...evidence.trustResult,
      chain: ["attacker", "fake-chain"],
    },
  };

  assert.equal(
    verifyAuthenticatedVerificationEvidence(
      forged,
      "verified-subject",
      NOW,
    ),
    false,
  );
});

test("verification cannot be replayed at another verification time", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-6",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  assert.equal(
    verifyAuthenticatedVerificationEvidence(
      evidence,
      "verified-subject",
      LATER,
    ),
    false,
  );
});

test("verification evidence cannot be accepted with an empty verifier chain", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-7",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  const forged = {
    ...evidence,
    verifierTrustChain: [],
  };

  assert.equal(
    verifyAuthenticatedVerificationEvidence(
      forged,
      "verified-subject",
      NOW,
    ),
    false,
  );
});

test("verification evidence without verifier chain input fails closed", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-8",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  const forged = {
    ...evidence,
    verifierTrustChainInput: undefined,
  } as unknown as typeof evidence;

  assert.doesNotThrow(() => {
    assert.equal(
      verifyAuthenticatedVerificationEvidence(
        forged,
        "verified-subject",
        NOW,
      ),
      false,
    );
  });
});

test("verification evidence without subject chain input fails closed", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-9",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  const forged = {
    ...evidence,
    trustChainInput: undefined,
  } as unknown as typeof evidence;

  assert.doesNotThrow(() => {
    assert.equal(
      verifyAuthenticatedVerificationEvidence(
        forged,
        "verified-subject",
        NOW,
      ),
      false,
    );
  });
});

test("tampered verifier trust-chain input is rejected", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-10",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  const forged = {
    ...evidence,
    verifierTrustChainInput: {
      ...evidence.verifierTrustChainInput,
      credential: {
        ...evidence.verifierTrustChainInput.credential,
        subject: "attacker",
      },
    },
  };

  assert.equal(
    verifyAuthenticatedVerificationEvidence(
      forged,
      "verified-subject",
      NOW,
    ),
    false,
  );
});

test("tampered subject trust-chain input is rejected", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-11",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  const forged = {
    ...evidence,
    trustChainInput: {
      ...evidence.trustChainInput,
      credential: {
        ...evidence.trustChainInput.credential,
        subject: "attacker",
      },
    },
  };

  assert.equal(
    verifyAuthenticatedVerificationEvidence(
      forged,
      "verified-subject",
      NOW,
    ),
    false,
  );
});

test("complete authenticated verification evidence remains valid", () => {
  const verifier = verifierFixture();
  const subject = subjectFixture();

  const evidence = createAuthenticatedVerification({
    id: "verification-12",
    subjectId: "verified-subject",
    verifier: verifier.verifier,
    verifiedAt: NOW,
    chain: subject,
  });

  assert.ok(evidence.verifierTrustChainInput);
  assert.ok(evidence.trustChainInput);

  assert.equal(
    verifyAuthenticatedVerificationEvidence(
      evidence,
      "verified-subject",
      NOW,
    ),
    true,
  );
});
