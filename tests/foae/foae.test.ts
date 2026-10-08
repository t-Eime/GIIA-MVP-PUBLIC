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
  authenticateVerifier,
  VERIFIER_AUTHORITY_CLAIM,
  VERIFIER_AUTHORITY_HASH_CLAIM,
} from "../../src/trust/verifier.js";

import {
  createAuthenticatedVerification,
} from "../../src/trust/verification.js";

import { KeySecurityBoundary } from "../../src/security/key-boundary.js";
import { canonicalize } from "../../src/core/canonical.js";
import { sha256 } from "../../src/core/security.js";
import type { Identity } from "../../src/identity/types.js";
import type { Authority } from "../../src/authority/types.js";
import type { AuthorizationRequest } from "../../src/authorization/types.js";
import type { Evidence } from "../../src/evidence/types.js";
import { createEvidenceHash } from "../../src/evidence/service.js";
import {
  verifyProducerOriginResultIntegrity,
  verifyProducerOriginEvidenceIntegrity,
} from "../../src/foae/service.js";
import {
  verifyProducerOrigin,
  FOAE_PRODUCER_AUTHORITY_CLAIM,
  FOAE_PRODUCER_AUTHORITY_HASH_CLAIM,
  FOAE_ARTIFACT_ID_CLAIM,
  FOAE_ARTIFACT_HASH_CLAIM,
  FOAE_ARTIFACT_VERSION_CLAIM,
  FOAE_ARTIFACT_TYPE_CLAIM,
  FOAE_ORGANIZATION_ID_CLAIM,
} from "../../src/foae/verification.js";
import { TrustRegistry } from "../../src/trust/registry.js";
import type { ProducerOriginClaim } from "../../src/foae/types.js";

const NOW = "2026-01-01T00:00:00.000Z";
const LATER = "2026-01-02T00:00:00.000Z";
const ARTIFACT_HASH = "a".repeat(64);

function identity(id: string): Identity {
  return {
    id,
    kind: "service",
    status: "active",
    provenance: "test",
    createdAt: NOW,
  };
}

function authority(id: string, holder: string): Authority {
  return {
    id,
    holderIdentityId: holder,
    trustCredentialId: "verifier-credential",
    scope: ["VERIFY:trust-subject", "ORIGIN:artifact-1"],
    issuedAt: NOW,
    status: "active",
    issuer: "test-issuer",
    provenance: "test",
  };
}

function authorization(
  identityId: string,
  authorityId: string,
): AuthorizationRequest {
  return {
    id: `authorization-${identityId}`,
    subjectIdentityId: identityId,
    authorityId,
    action: "VERIFY",
    resource: "trust-subject",
    requestedAt: NOW,
  };
}

function chain(
  subjectId: string,
  prefix: string,
  claims: Record<string, string> = {},
): TrustChainInput {
  const rootGenerated = createTrustKey(`${prefix}-root-key`, "root", "test", NOW);
  const anchorGenerated = createTrustKey(`${prefix}-anchor-key`, "anchor", "test", NOW);
  const delegationGenerated = createTrustKey(
    `${prefix}-delegation-key`,
    "delegation",
    "test",
    NOW,
  );

  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();

  rootBoundary.register(rootGenerated.key, rootGenerated.privateKeyPem, NOW);
  anchorBoundary.register(anchorGenerated.key, anchorGenerated.privateKeyPem, NOW);
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
  const verifierIdentity = identity("verifier-1");
  const verifierAuthority = authority(
    "verifier-authority",
    verifierIdentity.id,
  );

  const authorityHash = sha256(canonicalize(verifierAuthority));

  const verifierChain = chain(
    verifierIdentity.id,
    "verifier",
    {
      [VERIFIER_AUTHORITY_CLAIM]: verifierAuthority.id,
      [VERIFIER_AUTHORITY_HASH_CLAIM]: authorityHash,
    },
  );

  const verifier = authenticateVerifier({
    identity: verifierIdentity,
    authority: verifierAuthority,
    chain: verifierChain,
    authorizationRequest: authorization(
      verifierIdentity.id,
      verifierAuthority.id,
    ),
  });

  return verifier;
}

function producerFixture() {
  const producerIdentity = identity("producer-1");

  const producerAuthority: Authority = {
    id: "producer-authority-1",
    holderIdentityId: producerIdentity.id,
    trustCredentialId: "producer-credential",
    scope: ["ORIGIN:artifact-1"],
    issuedAt: NOW,
    status: "active",
    issuer: "test-issuer",
    provenance: "test",
  };

  const producerAuthorityHash =
    sha256(canonicalize(producerAuthority));

  const producerChain = chain(
    producerIdentity.id,
    "producer",
    {
      [FOAE_PRODUCER_AUTHORITY_CLAIM]:
        producerAuthority.id,
      [FOAE_PRODUCER_AUTHORITY_HASH_CLAIM]:
        producerAuthorityHash,
      [FOAE_ARTIFACT_ID_CLAIM]:
        "artifact-1",
      [FOAE_ARTIFACT_HASH_CLAIM]:
        ARTIFACT_HASH,
      [FOAE_ARTIFACT_VERSION_CLAIM]:
        "1.0.0",
      [FOAE_ARTIFACT_TYPE_CLAIM]:
        "software",
      [FOAE_ORGANIZATION_ID_CLAIM]:
        "organization-1",
    },
  );

  const verifier = verifierFixture();

  const authenticatedVerification =
    createAuthenticatedVerification({
      id: "authenticated-verification-1",
      subjectId: "producer-1",
      verifier,
      verifiedAt: NOW,
      chain: producerChain,
    });

  const trustRegistry = new TrustRegistry();

  trustRegistry.putKey(producerChain.rootKey);
  trustRegistry.putKey(producerChain.anchorKey);
  trustRegistry.putKey(producerChain.delegationKey);
  trustRegistry.putRoot(producerChain.root);
  trustRegistry.putAnchor(producerChain.anchor);
  trustRegistry.putDelegation(producerChain.delegation);
  trustRegistry.putCredential(producerChain.credential);

  return {
    producerIdentity,
    producerAuthority,
    producerChain,
    authenticatedVerification,
    trustRegistry,
  };
}

function claim(): ProducerOriginClaim {
  return {
    id: "origin-claim-1",
    organizationId: "organization-1",
    artifactId: "artifact-1",
    artifactType: "software",
    claimedProducerId: "producer-1",
    producerAuthorityRef: "producer-authority-1",
    originalArtifactHash: ARTIFACT_HASH,
    artifactVersion: "1.0.0",
    validFrom: NOW,
    observations: [
      {
        id: "observation-1",
        kind: "CLAIM",
        statement: "Producer claims original authorship of artifact.",
        source: "producer-1",
        observedAt: NOW,
        provenance: "test",
      },
    ],
    provenance: "test",
  };
}

function artifactEvidence(): Evidence {
  const unsigned: Omit<Evidence, "recordHash"> = {
    id: "artifact-evidence-1",
    kind: "attestation",
    subject: "artifact-1",
    action: "ORIGIN",
    occurredAt: NOW,
    recordedAt: NOW,
    source: "producer-1",
    contentHash: ARTIFACT_HASH,
    provenance: "test",
  };

  return {
    ...unsigned,
    recordHash: createEvidenceHash(unsigned),
  };
}

test("FOAE does not accept caller-controlled trust decisions", () => {
  const f = producerFixture();
  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "VERIFIED");
  assert.equal(result.producerId, "producer-1");
});

test("missing artifact-origin evidence cannot produce VERIFIED", () => {
  const f = producerFixture();

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("tampered artifact hash breaks origin verification", () => {
  const f = producerFixture();
  const c = claim();
  c.originalArtifactHash = "b".repeat(64);

  const result = verifyProducerOrigin({
    claim: c,
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("forged producer identity fails closed", () => {
  const f = producerFixture();
  const c = claim();
  c.claimedProducerId = "attacker";

  const result = verifyProducerOrigin({
    claim: c,
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("current registry revocation prevents current origin verification", () => {
  const f = producerFixture();

  f.trustRegistry.revoke({
    objectType: "credential",
    objectId: f.producerChain.credential.id,
    revokedAt: NOW,
    reason: "test revocation",
    authority: "test-authority",
    provenance: "test",
  });

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "REVOKED");
});

test("missing current trust state fails closed", () => {
  const f = producerFixture();
  const emptyRegistry = new TrustRegistry();

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: emptyRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("producer authority holder mismatch fails closed", () => {
  const f = producerFixture();

  const forgedAuthority: Authority = {
    ...f.producerAuthority,
    holderIdentityId: "attacker",
  };

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: forgedAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("producer authority claim substitution fails closed", () => {
  const f = producerFixture();
  const forgedChain = {
    ...f.producerChain,
    credential: {
      ...f.producerChain.credential,
      claims: {
        ...f.producerChain.credential.claims,
        [FOAE_PRODUCER_AUTHORITY_CLAIM]: "attacker-authority",
      },
    },
  };

  const forgedVerification = {
    ...f.authenticatedVerification,
    trustChainInput: forgedChain,
  };

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: forgedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("artifact id claim substitution fails closed", () => {
  const f = producerFixture();

  const forged = {
    ...f.authenticatedVerification,
    trustChainInput: {
      ...f.producerChain,
      credential: {
        ...f.producerChain.credential,
        claims: {
          ...f.producerChain.credential.claims,
          [FOAE_ARTIFACT_ID_CLAIM]: "attacker-artifact",
        },
      },
    },
  };

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: forged,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("artifact hash claim substitution fails closed", () => {
  const f = producerFixture();

  const forged = {
    ...f.authenticatedVerification,
    trustChainInput: {
      ...f.producerChain,
      credential: {
        ...f.producerChain.credential,
        claims: {
          ...f.producerChain.credential.claims,
          [FOAE_ARTIFACT_HASH_CLAIM]: "b".repeat(64),
        },
      },
    },
  };

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: forged,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("artifact version claim substitution fails closed", () => {
  const f = producerFixture();

  const forged = {
    ...f.authenticatedVerification,
    trustChainInput: {
      ...f.producerChain,
      credential: {
        ...f.producerChain.credential,
        claims: {
          ...f.producerChain.credential.claims,
          [FOAE_ARTIFACT_VERSION_CLAIM]: "9.9.9",
        },
      },
    },
  };

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: forged,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("artifact type claim substitution fails closed", () => {
  const f = producerFixture();

  const forged = {
    ...f.authenticatedVerification,
    trustChainInput: {
      ...f.producerChain,
      credential: {
        ...f.producerChain.credential,
        claims: {
          ...f.producerChain.credential.claims,
          [FOAE_ARTIFACT_TYPE_CLAIM]: "hardware",
        },
      },
    },
  };

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: forged,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "UNVERIFIABLE");
});

test("verification at validity start is accepted", () => {
  const f = producerFixture();

  const result = verifyProducerOrigin({
    claim: claim(),
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "VERIFIED");
});

test("verification at validity end is expired", () => {
  const f = producerFixture();
  const c = claim();
  c.validUntil = LATER;

  const result = verifyProducerOrigin({
    claim: c,
    producerAuthority: f.producerAuthority,
    evidenceChain: [artifactEvidence()],
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: LATER,
    trustRegistry: f.trustRegistry,
  });

  assert.equal(result.status, "EXPIRED");
});

test("tampered verification result fails integrity verification", () => {
  const f = producerFixture();

  const result = verifyProducerOrigin({
    claim: claim(),
    evidenceChain: [artifactEvidence()],
    producerAuthority: f.producerAuthority,
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  const forged = {
    ...result,
    status: "VERIFIED" as const,
    producerId: "attacker",
  };

  assert.equal(verifyProducerOriginResultIntegrity(forged), false);
});

test("FOAE evidence binding rejects mismatched producer", () => {
  const f = producerFixture();
  const c = claim();

  const result = verifyProducerOrigin({
    claim: c,
    evidenceChain: [artifactEvidence()],
    producerAuthority: f.producerAuthority,
    authenticatedVerification: f.authenticatedVerification,
    verifiedAt: NOW,
    trustRegistry: f.trustRegistry,
  });

  const evidence = {
    claim: c,
    verification: {
      ...result,
      producerId: "attacker",
      resultHash: result.resultHash,
    },
    recordHash: "0".repeat(64),
  };

  assert.equal(verifyProducerOriginEvidenceIntegrity(evidence), false);
});
