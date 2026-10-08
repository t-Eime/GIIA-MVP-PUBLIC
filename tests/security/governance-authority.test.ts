import assert from "node:assert/strict";
import test from "node:test";

import {
  createGovernanceAuthorityCertificate,
  governanceAuthorityDecisionDigest,
  createGovernanceAuthoritySet,
  generateGovernanceAuthorityMember,
  signGovernanceAuthorityMember,
  verifyGovernanceAuthorityCertificate,
  type GovernanceAuthorityKeyPair,
} from "../../src/security/governance-authority.js";

function fixture() {
  const members: GovernanceAuthorityKeyPair[] = Array.from(
    { length: 5 },
    (_, index) =>
      generateGovernanceAuthorityMember(
        `governance-member-${index + 1}`,
      ),
  );

  const authoritySet = createGovernanceAuthoritySet(
    "giia-governance-authority-v1",
    1,
    members.map((member) => member.member),
  );

  return { members, authoritySet };
}

const DECISION = {
  decisionId: "decision-001",
  requestId: "request-001",
  decision: "ALLOW",
  authoritative: true,
  action: "TEST_ACTION",
  target: "TEST_TARGET",
};

test("3-of-5 governance authority accepts exactly three valid members", () => {
  const { members, authoritySet } = fixture();

  const certificate = createGovernanceAuthorityCertificate(
    DECISION,
    authoritySet,
    members.slice(0, 3),
  );

  const result = verifyGovernanceAuthorityCertificate(
    DECISION,
    certificate,
    authoritySet,
  );

  assert.equal(result.valid, true);
  assert.equal(result.reason, "GOVERNANCE_AUTHORITY_VERIFIED");
});

test("one compromised member cannot create a quorum", () => {
  const { members, authoritySet } = fixture();

  assert.throws(
    () =>
      createGovernanceAuthorityCertificate(
        DECISION,
        authoritySet,
        [members[0] !],
      ),
    /GOVERNANCE_AUTHORITY_QUORUM_NOT_MET/,
  );
});

test("two compromised members cannot create a quorum", () => {
  const { members, authoritySet } = fixture();

  assert.throws(
    () =>
      createGovernanceAuthorityCertificate(
        DECISION,
        authoritySet,
        members.slice(0, 2),
      ),
    /GOVERNANCE_AUTHORITY_QUORUM_NOT_MET/,
  );
});

test("four or five valid members satisfy the quorum", () => {
  const { members, authoritySet } = fixture();

  for (const count of [4, 5]) {
    const certificate = createGovernanceAuthorityCertificate(
      DECISION,
      authoritySet,
      members.slice(0, count),
    );

    const result = verifyGovernanceAuthorityCertificate(
      DECISION,
      certificate,
      authoritySet,
    );

    assert.equal(result.valid, true);
  }
});

test("duplicate signer cannot count twice", () => {
  const { members, authoritySet } = fixture();

  assert.throws(
    () =>
      createGovernanceAuthorityCertificate(
        DECISION,
        authoritySet,
        [members[0] !, members[0] !, members[1] !],
      ),
    /GOVERNANCE_AUTHORITY_DUPLICATE_SIGNER/,
  );
});

test("revoked member cannot satisfy the quorum", () => {
  const { members, authoritySet } = fixture();

  const revokedMembers = authoritySet.members.map((member) =>
    member.memberId === members[0]!.member.memberId
      ? { ...member, status: "revoked" as const }
      : member,
  );

  const revokedSet = createGovernanceAuthoritySet(
    authoritySet.setId,
    authoritySet.version,
    revokedMembers,
  );

  const certificate = createGovernanceAuthorityCertificate(
    DECISION,
    authoritySet,
    members.slice(0, 3),
  );

  const result = verifyGovernanceAuthorityCertificate(
    DECISION,
    certificate,
    revokedSet,
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_AUTHORITY_SIGNER_NOT_ACTIVE",
  );
});

test("decision mutation invalidates the certificate", () => {
  const { members, authoritySet } = fixture();

  const certificate = createGovernanceAuthorityCertificate(
    DECISION,
    authoritySet,
    members.slice(0, 3),
  );

  const mutatedDecision = {
    ...DECISION,
    target: "TAMPERED_TARGET",
  };

  const result = verifyGovernanceAuthorityCertificate(
    mutatedDecision,
    certificate,
    authoritySet,
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_AUTHORITY_DECISION_DIGEST_MISMATCH",
  );
});

test("wrong authority set is rejected", () => {
  const first = fixture();
  const second = fixture();

  const substitutedAuthoritySet = createGovernanceAuthoritySet(
    "attacker-governance-authority",
    second.authoritySet.version,
    second.authoritySet.members,
  );

  const certificate = createGovernanceAuthorityCertificate(
    DECISION,
    first.authoritySet,
    first.members.slice(0, 3),
  );

  const result = verifyGovernanceAuthorityCertificate(
    DECISION,
    certificate,
    substitutedAuthoritySet,
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_AUTHORITY_SET_MISMATCH",
  );
});

test("caller cannot substitute a member public key", () => {
  const { members, authoritySet } = fixture();

  const certificate = createGovernanceAuthorityCertificate(
    DECISION,
    authoritySet,
    members.slice(0, 3),
  );

  const substitutedMembers = authoritySet.members.map(
    (member, index) =>
      index === 0
        ? {
            memberId: member.memberId,
            purpose: member.purpose,
            status: member.status,
            publicKeyPem: members[3]!.member.publicKeyPem,
          }
        : {
            memberId: member.memberId,
            purpose: member.purpose,
            status: member.status,
            publicKeyPem: member.publicKeyPem,
          },
  );

  const substitutedSet = createGovernanceAuthoritySet(
    authoritySet.setId,
    authoritySet.version,
    substitutedMembers,
  );

  const result = verifyGovernanceAuthorityCertificate(
    DECISION,
    certificate,
    substitutedSet,
  );

  assert.equal(result.valid, false);
});

test("tampered signature fails closed", () => {
  const { members, authoritySet } = fixture();

  const certificate = createGovernanceAuthorityCertificate(
    DECISION,
    authoritySet,
    members.slice(0, 3),
  );

  const tamperedSignatures = certificate.signatures.map(
    (signature, index) =>
      index === 0
        ? {
            memberId: signature.memberId,
            signatureBase64: Buffer.from("tampered").toString("base64"),
          }
        : {
            memberId: signature.memberId,
            signatureBase64: signature.signatureBase64,
          },
  );

  const tamperedCertificate = {
    algorithm: certificate.algorithm,
    setId: certificate.setId,
    setVersion: certificate.setVersion,
    decisionDigest: certificate.decisionDigest,
    signatures: tamperedSignatures,
  };

  const result = verifyGovernanceAuthorityCertificate(
    DECISION,
    tamperedCertificate,
    authoritySet,
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_AUTHORITY_SIGNATURE_INVALID",
  );
});

test("manually forged signature from an unregistered key is rejected", () => {
  const { members, authoritySet } = fixture();

  const rogue = generateGovernanceAuthorityMember(
    "rogue-member",
  );

  const rogueSignature = signGovernanceAuthorityMember(
    DECISION,
    rogue,
  );

  const validSignature1 = signGovernanceAuthorityMember(
    DECISION,
    members[0]!,
  );

  const validSignature2 = signGovernanceAuthorityMember(
    DECISION,
    members[1]!,
  );

  const certificate = {
    algorithm: "ED25519-MULTISIG-3-OF-5" as const,
    setId: authoritySet.setId,
    setVersion: authoritySet.version,
    decisionDigest:
      governanceAuthorityDecisionDigest(DECISION),
    signatures: [
      rogueSignature,
      validSignature1,
      validSignature2,
    ],
  };

  const result = verifyGovernanceAuthorityCertificate(
    DECISION,
    certificate,
    authoritySet,
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_AUTHORITY_SIGNER_NOT_REGISTERED",
  );
});
