import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";

import {
  createHumanApprovalKeyPair,
  evaluateConstitutionalAmendment,
  listConstitutionalAmendmentEvidence,
  signHumanApproval,
  verifyConstitutionalAmendmentEvidenceChain,
} from "../../src/constitution/amendment.js";

import {
  createAnchorWithSecureKey,
  createCredentialWithSecureKey,
  createDelegationWithSecureKey,
  createRoot,
  createTrustKey,
  type TrustChainInput,
} from "../../src/trust/service.js";

import { KeySecurityBoundary } from "../../src/security/key-boundary.js";
import type { TrustKey } from "../../src/trust/types.js";

import {
  CONSTITUTIONAL_INVARIANTS,
  type ConstitutionalInvariant,
} from "../../src/constitution/invariant-registry.js";

import type { Identity } from "../../src/identity/types.js";
import type { Authority } from "../../src/authority/types.js";
import {
  createGovernanceAuthorityCertificate,
  createGovernanceAuthoritySet,
  generateGovernanceAuthorityMember,
} from "../../src/security/governance-authority.js";

function publicKeyPem(
  key: ReturnType<typeof createHumanApprovalKeyPair>["publicKey"],
): string {
  return key.export({
    type: "spki",
    format: "pem",
  }) as string;
}

function makeProposal(
  proposed: readonly ConstitutionalInvariant[] = CONSTITUTIONAL_INVARIANTS,
) {
  const keys = createHumanApprovalKeyPair();
  const proposedAt = "2026-09-29T12:00:00.000Z";

  const identity: Identity = {
    id: "human-approver-001",
    kind: "human",
    status: "active",
    provenance: "test-human-identity",
    createdAt: proposedAt,
  };

  const authority: Authority = {
    id: "constitutional-authority-001",
    holderIdentityId: identity.id,
    trustCredentialId: "test-trust-credential-001",
    scope: ["constitutional:amendment"],
    issuedAt: proposedAt,
    status: "active",
    issuer: "test-constitutional-issuer",
    provenance: "test-authority-provenance",
  };

  const approvalKeyId = "constitutional-approval-key";
  const approvalPublicKeyPem = publicKeyPem(keys.publicKey);

  const approvalTrustKey: TrustKey = {
    id: approvalKeyId,
    algorithm: "Ed25519",
    purpose: "execution",
    publicKeyPem: approvalPublicKeyPem,
    createdAt: proposedAt,
    notBefore: proposedAt,
    status: "active",
    provenance: "test-constitutional-approval-key",
  };

  const keyBoundary = new KeySecurityBoundary();

  keyBoundary.register(
    approvalTrustKey,
    keys.privateKey.export({
      type: "pkcs8",
      format: "pem",
    }) as string,
    proposedAt,
  );

  const prefix = "amendment-human-001";

  const rootGenerated = createTrustKey(
    `${prefix}-root-key`,
    "root",
    "test",
    proposedAt,
  );

  const anchorGenerated = createTrustKey(
    `${prefix}-anchor-key`,
    "anchor",
    "test",
    proposedAt,
  );

  const delegationGenerated = createTrustKey(
    `${prefix}-delegation-key`,
    "delegation",
    "test",
    proposedAt,
  );

  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();

  rootBoundary.register(
    rootGenerated.key,
    rootGenerated.privateKeyPem,
    proposedAt,
  );

  anchorBoundary.register(
    anchorGenerated.key,
    anchorGenerated.privateKeyPem,
    proposedAt,
  );

  delegationBoundary.register(
    delegationGenerated.key,
    delegationGenerated.privateKeyPem,
    proposedAt,
  );

  const root = createRoot(
    `${prefix}-root`,
    `${prefix}-root-subject`,
    rootGenerated.key.id,
    proposedAt,
    "test",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: `${prefix}-anchor`,
      subject: `${prefix}-anchor-subject`,
      rootId: root.id,
      signingKeyId: rootGenerated.key.id,
      constraints: ["issue:credential"],
      issuedAt: proposedAt,
      status: "active",
      provenance: "test",
    },
    {
      boundary: rootBoundary,
      keyId: rootGenerated.key.id,
      purpose: "root",
      at: proposedAt,
    },
  );

  const delegation = createDelegationWithSecureKey(
    {
      id: `${prefix}-delegation`,
      issuerAnchorId: anchor.id,
      delegateeId: identity.id,
      signingKeyId: anchorGenerated.key.id,
      constraints: ["credential:issue"],
      issuedAt: proposedAt,
      status: "active",
      provenance: "test",
    },
    {
      boundary: anchorBoundary,
      keyId: anchorGenerated.key.id,
      purpose: "anchor",
      at: proposedAt,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: authority.trustCredentialId,
      subject: identity.id,
      issuerDelegationId: delegation.id,
      claims: {
        "giia.constitutional.approval.identityId": identity.id,
        "giia.constitutional.approval.authorityId": authority.id,
        "giia.constitutional.approval.keyId": approvalKeyId,
        "giia.constitutional.approval.publicKeyFingerprint":
          createHash("sha256")
            .update(approvalPublicKeyPem, "utf8")
            .digest("hex"),
      },
      issuedAt: proposedAt,
      status: "active",
      provenance: "test",
    },
    {
      boundary: delegationBoundary,
      keyId: delegationGenerated.key.id,
      purpose: "delegation",
      at: proposedAt,
    },
  );

  const trustChain: TrustChainInput = {
    root,
    rootKey: rootGenerated.key,
    anchor,
    anchorKey: anchorGenerated.key,
    delegation,
    delegationKey: delegationGenerated.key,
    credential,
    at: proposedAt,
  };

  const unsigned = {
    amendmentId: `TEST-AMENDMENT-${Date.now()}-${Math.random()}`,
    baseVersion: "GIIA-CONSTITUTION-v0.1.1",
    proposedVersion: "GIIA-CONSTITUTION-v0.1.2",
    reason: "Increase constitutional verification coverage.",
    proposerId: "human-proposer-001",
    proposedAt,
    baseline: CONSTITUTIONAL_INVARIANTS,
    proposed,
  };

  const governanceMembers = Array.from(
    { length: 5 },
    (_, index) =>
      generateGovernanceAuthorityMember(
        `constitutional-governance-member-${index + 1}`,
      ),
  );

  const governanceAuthoritySet = createGovernanceAuthoritySet(
    `constitutional-test-authority-${Date.now()}-${Math.random()}`,
    1,
    governanceMembers.map((member) => member.member),
  );

  const unsignedWithAuthority = {
    ...unsigned,
    governanceAuthoritySet,
  };

  const governanceAuthorityCertificate =
    createGovernanceAuthorityCertificate(
      unsignedWithAuthority,
      governanceAuthoritySet,
      governanceMembers.slice(0, 3),
    );

  const approval = signHumanApproval(
    unsignedWithAuthority,
    identity.id,
    authority.id,
    keys.privateKey,
    approvalPublicKeyPem,
    proposedAt,
    approvalKeyId,
  );

  return Object.freeze({
    proposal: Object.freeze({
      ...unsignedWithAuthority,
      governanceAuthorityCertificate,
      approval,
    }),
    identity,
    authority,
    trustChain,
    keyBoundary,
    governanceAuthoritySet,
    governanceAuthorityMembers: governanceMembers,
    approvalKey: approvalTrustKey,
  });
}

test("valid human-approved constitutional amendment is accepted", () => {
  const fixture = makeProposal();

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, true);
  assert.equal(result.decision, "APPROVED");
  assert.ok(result.evidence);
  assert.equal(verifyConstitutionalAmendmentEvidenceChain(), true);
});

test("P0-D: human approval alone is insufficient without governance quorum", () => {
  const fixture = makeProposal();

  const withoutGovernance = {
    ...fixture.proposal,
    governanceAuthorityCertificate: {
      ...fixture.proposal.governanceAuthorityCertificate,
      signatures: [],
    },
  };

  const result = evaluateConstitutionalAmendment(
    withoutGovernance,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: governance quorum alone is insufficient without valid human approval", () => {
  const fixture = makeProposal();

  const forgedApproval = {
    ...fixture.proposal.approval,
    signatureBase64: Buffer.from("forged-human-approval").toString("base64"),
  };

  const result = evaluateConstitutionalAmendment(
    {
      ...fixture.proposal,
      approval: forgedApproval,
    },
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: two-of-five governance quorum is insufficient", () => {
  const fixture = makeProposal();

  const { approval: _approval, governanceAuthorityCertificate: _certificate, ...unsigned } =
    fixture.proposal;

  assert.throws(
    () =>
      createGovernanceAuthorityCertificate(
        unsigned,
        fixture.governanceAuthoritySet,
        fixture.governanceAuthorityMembers.slice(0, 2),
      ),
    /GOVERNANCE_AUTHORITY_QUORUM_NOT_MET/,
  );
});

test("P0-D: wrong governance authority set is denied", () => {
  const fixture = makeProposal();

  const otherMembers = Array.from(
    { length: 5 },
    (_, index) =>
      generateGovernanceAuthorityMember(
        `wrong-constitutional-governance-member-${index + 1}`,
      ),
  );

  const wrongSet = createGovernanceAuthoritySet(
    `wrong-constitutional-authority-${Date.now()}-${Math.random()}`,
    1,
    otherMembers.map((member) => member.member),
  );

  const tampered = {
    ...fixture.proposal,
    governanceAuthoritySet: wrongSet,
  };

  const result = evaluateConstitutionalAmendment(
    tampered,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: amendment tampering after governance quorum is denied", () => {
  const fixture = makeProposal();

  const tampered = {
    ...fixture.proposal,
    reason: "Tampered after governance quorum.",
  };

  const result = evaluateConstitutionalAmendment(
    tampered,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: amendment tampering after human approval is denied", () => {
  const fixture = makeProposal();

  const tampered = {
    ...fixture.proposal,
    proposedAt: "2026-09-29T12:01:00.000Z",
  };

  const result = evaluateConstitutionalAmendment(
    tampered,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: revoked governance signer is denied", () => {
  const fixture = makeProposal();

  const revokedMembers = fixture.governanceAuthorityMembers.map((entry, index) =>
    index === 0
      ? {
          ...entry,
          member: {
            ...entry.member,
            status: "revoked" as const,
          },
        }
      : entry,
  );

  const revokedSet = createGovernanceAuthoritySet(
    `revoked-constitutional-authority-${Date.now()}-${Math.random()}`,
    1,
    revokedMembers.map((entry) => entry.member),
  );

  const unsigned = {
    ...fixture.proposal,
    governanceAuthoritySet: revokedSet,
  };

  const certificate = createGovernanceAuthorityCertificate(
    unsigned,
    revokedSet,
    revokedMembers.slice(1, 4),
  );

  const result = evaluateConstitutionalAmendment(
    {
      ...fixture.proposal,
      governanceAuthoritySet: revokedSet,
      governanceAuthorityCertificate: certificate,
    },
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: quarantined governance signer is denied", () => {
  const fixture = makeProposal();

  const quarantinedMembers = fixture.governanceAuthorityMembers.map((entry, index) =>
    index === 0
      ? {
          ...entry,
          member: {
            ...entry.member,
            status: "quarantined" as const,
          },
        }
      : entry,
  );

  const quarantinedSet = createGovernanceAuthoritySet(
    `quarantined-constitutional-authority-${Date.now()}-${Math.random()}`,
    1,
    quarantinedMembers.map((entry) => entry.member),
  );

  const unsigned = {
    ...fixture.proposal,
    governanceAuthoritySet: quarantinedSet,
  };

  const certificate = createGovernanceAuthorityCertificate(
    unsigned,
    quarantinedSet,
    quarantinedMembers.slice(1, 4),
  );

  const result = evaluateConstitutionalAmendment(
    {
      ...fixture.proposal,
      governanceAuthoritySet: quarantinedSet,
      governanceAuthorityCertificate: certificate,
    },
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: expired governance signer is denied", () => {
  const fixture = makeProposal();

  const expiredMembers = fixture.governanceAuthorityMembers.map((entry, index) =>
    index === 0
      ? {
          ...entry,
          member: {
            ...entry.member,
            status: "expired" as const,
          },
        }
      : entry,
  );

  const expiredSet = createGovernanceAuthoritySet(
    `expired-constitutional-authority-${Date.now()}-${Math.random()}`,
    1,
    expiredMembers.map((entry) => entry.member),
  );

  const unsigned = {
    ...fixture.proposal,
    governanceAuthoritySet: expiredSet,
  };

  const certificate = createGovernanceAuthorityCertificate(
    unsigned,
    expiredSet,
    expiredMembers.slice(1, 4),
  );

  const result = evaluateConstitutionalAmendment(
    {
      ...fixture.proposal,
      governanceAuthoritySet: expiredSet,
      governanceAuthorityCertificate: certificate,
    },
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: governance certificate mutation is denied", () => {
  const fixture = makeProposal();

  const tamperedCertificate = {
    ...fixture.proposal.governanceAuthorityCertificate,
    signatures: fixture.proposal.governanceAuthorityCertificate.signatures.map(
      (signature, index) =>
        index === 0
          ? {
              ...signature,
              signatureBase64: Buffer.from("tampered-governance-signature").toString(
                "base64",
              ),
            }
          : signature,
    ),
  };

  const result = evaluateConstitutionalAmendment(
    {
      ...fixture.proposal,
      governanceAuthorityCertificate: tamperedCertificate,
    },
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: governance authority set mutation after quorum is denied", () => {
  const fixture = makeProposal();

  const mutatedSet = {
    ...fixture.governanceAuthoritySet,
    version: fixture.governanceAuthoritySet.version + 1,
  };

  const result = evaluateConstitutionalAmendment(
    {
      ...fixture.proposal,
      governanceAuthoritySet: mutatedSet,
    },
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("P0-D: only exact human approval plus exact governance quorum can approve", () => {
  const fixture = makeProposal();

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, true);
  assert.equal(result.decision, "APPROVED");
});

test("constitutional amendment without valid approval is denied", () => {
  const fixture = makeProposal();

  const forged = {
    ...fixture.proposal,
    approval: {
      ...fixture.proposal.approval,
      signatureBase64: Buffer.from("forged").toString("base64"),
    },
  };

  const result = evaluateConstitutionalAmendment(
    forged,
    fixture.identity,
    fixture.authority,
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("constitutional downgrade cannot be approved by a valid signature", () => {
  const fixture = makeProposal(
    CONSTITUTIONAL_INVARIANTS.map((item, index) =>
      index === 0
        ? { ...item, severity: "NORMAL" }
        : item,
    ),
  );

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "SEVERITY_WEAKENED",
    ),
  );
});

test("amendment proposal tampering invalidates human approval", () => {
  const fixture = makeProposal();

  const tampered = {
    ...fixture.proposal,
    reason: "Tampered constitutional amendment.",
  };

  const result = evaluateConstitutionalAmendment(
    tampered,
    fixture.identity,
    fixture.authority,
  );

  assert.equal(result.allowed, false);
});

test("amendment replay is denied", () => {
  const fixture = makeProposal();

  const first = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  const second = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(first.allowed, true);
  assert.equal(second.allowed, false);
});

test("amendment evidence is append-only and chained", () => {
  const beforeEvidence = listConstitutionalAmendmentEvidence();
  const before = beforeEvidence.length;
  const previousEvidenceHash =
    before === 0 ? null : beforeEvidence[before - 1]!.evidenceHash;

  const first = makeProposal();
  const second = makeProposal();

  const firstResult = evaluateConstitutionalAmendment(
    first.proposal,
    first.identity,
    first.authority,
    {
      trustChain: first.trustChain,
      keyBoundary: first.keyBoundary,
      governanceAuthoritySet: first.governanceAuthoritySet,
    },
  );

  const secondResult = evaluateConstitutionalAmendment(
    second.proposal,
    second.identity,
    second.authority,
    {
      trustChain: second.trustChain,
      keyBoundary: second.keyBoundary,
      governanceAuthoritySet: second.governanceAuthoritySet,
    },
  );

  assert.equal(firstResult.allowed, true);
  assert.equal(secondResult.allowed, true);

  const after = listConstitutionalAmendmentEvidence();

  assert.equal(after.length, before + 2);

  const firstEvidence = after[after.length - 2]!;
  const secondEvidence = after[after.length - 1]!;

  assert.equal(firstEvidence.amendmentId, first.proposal.amendmentId);
  assert.equal(secondEvidence.amendmentId, second.proposal.amendmentId);

  assert.equal(
    firstEvidence.previousEvidenceHash,
    previousEvidenceHash,
  );
  assert.equal(
    secondEvidence.previousEvidenceHash,
    firstEvidence.evidenceHash,
  );

  assert.equal(verifyConstitutionalAmendmentEvidenceChain(), true);

  const snapshot = listConstitutionalAmendmentEvidence();
  assert.equal(
    listConstitutionalAmendmentEvidence().length,
    snapshot.length,
  );
});;

test("human approval binds approver and authority metadata cryptographically", () => {
  const fixture = makeProposal();

  const tampered = {
    ...fixture.proposal,
    approval: {
      ...fixture.proposal.approval,
      authorityId: "different-authority",
    },
  };

  const result = evaluateConstitutionalAmendment(
    tampered,
    fixture.identity,
    fixture.authority,
  );

  assert.equal(result.allowed, false);
});

test("AI identity cannot approve a constitutional amendment", () => {
  const fixture = makeProposal();

  const aiIdentity: Identity = {
    ...fixture.identity,
    kind: "ai_system",
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    aiIdentity,
    fixture.authority,
  );

  assert.equal(result.allowed, false);
});

test("wrong human identity cannot approve a constitutional amendment", () => {
  const fixture = makeProposal();

  const wrongHuman: Identity = {
    ...fixture.identity,
    id: "different-human",
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    wrongHuman,
    fixture.authority,
  );

  assert.equal(result.allowed, false);
});

test("authority held by another identity cannot approve amendment", () => {
  const fixture = makeProposal();

  const otherAuthority: Authority = {
    ...fixture.authority,
    holderIdentityId: "another-human",
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    otherAuthority,
  );

  assert.equal(result.allowed, false);
});

test("revoked human identity cannot approve amendment", () => {
  const fixture = makeProposal();

  const revoked: Identity = {
    ...fixture.identity,
    status: "revoked",
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    revoked,
    fixture.authority,
  );

  assert.equal(result.allowed, false);
});

test("expired amendment authority cannot approve amendment", () => {
  const fixture = makeProposal();

  const expired: Authority = {
    ...fixture.authority,
    expiresAt: new Date(
      Date.parse(fixture.proposal.proposedAt) - 1000,
    ).toISOString(),
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    expired,
  );

  assert.equal(result.allowed, false);
});

test("authority without amendment scope cannot approve amendment", () => {
  const fixture = makeProposal();

  const insufficient: Authority = {
    ...fixture.authority,
    scope: ["constitutional:review"],
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    insufficient,
  );

  assert.equal(result.allowed, false);
});

test("amendment validation is read-only and does not emit signing lifecycle events", () => {
  const fixture = makeProposal();

  const before = fixture.keyBoundary.lifecycleEvents();

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  const after = fixture.keyBoundary.lifecycleEvents();

  assert.equal(result.allowed, true);
  assert.deepEqual(after, before);
  assert.equal(
    after.some((event) => event.event === "USED_FOR_SIGNING"),
    false,
  );
});

test("AI identity with valid human approval key is denied", () => {
  const fixture = makeProposal();

  const aiIdentity: Identity = {
    ...fixture.identity,
    kind: "ai_system",
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    aiIdentity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("Human A with Human B approval key is denied", () => {
  const fixture = makeProposal();
  const otherKeys = createHumanApprovalKeyPair();
  const otherPublicKeyPem = publicKeyPem(otherKeys.publicKey);

  const { approval: _ignoredApproval, ...unsignedProposal } = fixture.proposal;

  const approval = signHumanApproval(
    unsignedProposal,
    fixture.identity.id,
    fixture.authority.id,
    otherKeys.privateKey,
    otherPublicKeyPem,
    fixture.proposal.approval.approvedAt,
    fixture.proposal.approval.keyId,
  );

  const tampered = {
    ...fixture.proposal,
    approval,
  };

  const result = evaluateConstitutionalAmendment(
    tampered,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("unregistered approval key is denied", () => {
  const fixture = makeProposal();

  const unregisteredKeys = createHumanApprovalKeyPair();
  const unregisteredPublicKeyPem = publicKeyPem(
    unregisteredKeys.publicKey,
  );

  const { approval: _ignoredApproval, ...unsignedProposal } = fixture.proposal;

  const approval = signHumanApproval(
    unsignedProposal,
    fixture.identity.id,
    fixture.authority.id,
    unregisteredKeys.privateKey,
    unregisteredPublicKeyPem,
    fixture.proposal.approval.approvedAt,
    "unregistered-approval-key",
  );

  const result = evaluateConstitutionalAmendment(
    {
      ...fixture.proposal,
      approval,
    },
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("revoked approval key is denied", () => {
  const fixture = makeProposal();

  fixture.keyBoundary.revoke(
    fixture.approvalKey.id,
    "2026-09-29T13:00:00.000Z",
    "test revocation",
  );

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("quarantined approval key is denied", () => {
  const fixture = makeProposal();

  fixture.keyBoundary.quarantine(
    fixture.approvalKey.id,
    "2026-09-29T13:00:00.000Z",
    "test quarantine",
  );

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("expired approval key is denied", () => {
  const fixture = makeProposal();
  const expiredBoundary = new KeySecurityBoundary();

  const expiredKeys = createHumanApprovalKeyPair();
  const expiredPublicKeyPem = publicKeyPem(expiredKeys.publicKey);

  const expiredKey: TrustKey = {
    ...fixture.approvalKey,
    id: "expired-constitutional-approval-key",
    publicKeyPem: expiredPublicKeyPem,
    notAfter: "2026-09-29T12:00:00.000Z",
  };

  expiredBoundary.register(
    expiredKey,
    expiredKeys.privateKey.export({
      type: "pkcs8",
      format: "pem",
    }) as string,
    "2026-09-29T11:00:00.000Z",
  );

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: expiredBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("wrong-purpose approval key is denied", () => {
  const fixture = makeProposal();

  const wrongPurposeBoundary = new KeySecurityBoundary();

  const wrongPurposeKeys = createHumanApprovalKeyPair();
  const wrongPurposePublicKeyPem = publicKeyPem(
    wrongPurposeKeys.publicKey,
  );

  const wrongPurposeKey: TrustKey = {
    ...fixture.approvalKey,
    id: "wrong-purpose-constitutional-approval-key",
    purpose: "root",
    publicKeyPem: wrongPurposePublicKeyPem,
  };

  wrongPurposeBoundary.register(
    wrongPurposeKey,
    wrongPurposeKeys.privateKey.export({
      type: "pkcs8",
      format: "pem",
    }) as string,
    fixture.proposal.approval.approvedAt,
  );

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: wrongPurposeBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("substituted credential is denied", () => {
  const fixture = makeProposal();

  const substitutedChain = {
    ...fixture.trustChain,
    credential: {
      ...fixture.trustChain.credential,
      subject: "different-human",
    },
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    fixture.authority,
    {
      trustChain: substitutedChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});

test("substituted authority is denied", () => {
  const fixture = makeProposal();

  const substitutedAuthority: Authority = {
    ...fixture.authority,
    id: "different-constitutional-authority",
  };

  const result = evaluateConstitutionalAmendment(
    fixture.proposal,
    fixture.identity,
    substitutedAuthority,
    {
      trustChain: fixture.trustChain,
      keyBoundary: fixture.keyBoundary,
      governanceAuthoritySet: fixture.governanceAuthoritySet,
    },
  );

  assert.equal(result.allowed, false);
  assert.equal(result.decision, "DENIED");
});
