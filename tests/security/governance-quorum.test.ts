import assert from "node:assert/strict";
import test from "node:test";

import {
  createGovernanceQuorumCertificate,
  generateGovernanceQuorumMember,
  governanceDecisionDigest,
  signGovernanceQuorumMember,
  verifyGovernanceQuorumCertificate,
} from "../../src/security/governance-quorum.js";

function fixture() {
  const members = Array.from(
    { length: 5 },
    (_, index) =>
      generateGovernanceQuorumMember(
        `governance-member-${index + 1}`,
      ),
  );

  const decision = {
    decisionId: "decision-1",
    requestId: "request-1",
    action: "TEST_ACTION",
    target: "TEST_TARGET",
    constitutionVersion: "GIIA-CONSTITUTION-1.0",
    nonce: "nonce-1",
  };

  return { members, decision };
}

test("3-of-5 governance quorum permits exactly three valid members", () => {
  const { members, decision } = fixture();

  const certificate = createGovernanceQuorumCertificate(
    decision,
    members,
  );

  const result = verifyGovernanceQuorumCertificate(
    decision,
    certificate,
    members.map(({ member }) => member),
  );

  assert.equal(result.valid, true, result.reason);
});

test("2-of-5 governance quorum fails closed", () => {
  const { members, decision } = fixture();

  const digest = createGovernanceQuorumCertificate(
    decision,
    members,
  );

  const certificate = {
    ...digest,
    signatures: digest.signatures.slice(0, 2),
  };

  const result = verifyGovernanceQuorumCertificate(
    decision,
    certificate,
    members.map(({ member }) => member),
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_QUORUM_THRESHOLD_NOT_MET",
  );
});

test("four or five valid members still satisfy the quorum", () => {
  const { members, decision } = fixture();

  const signatures = members.map((member) =>
    signGovernanceQuorumMember(decision, member),
  );

  const certificate = {
    algorithm: "Ed25519-QUORUM-3-OF-5" as const,
    quorum: 3 as const,
    memberCount: 5 as const,
    decisionDigest: digestFor(decision),
    signatures,
  };

  const result = verifyGovernanceQuorumCertificate(
    decision,
    certificate,
    members.map(({ member }) => member),
  );

  assert.equal(result.valid, true, result.reason);
});

test("duplicate signer is rejected", () => {
  const { members, decision } = fixture();

  const signature = signGovernanceQuorumMember(
    decision,
    members[0]!,
  );

  const certificate = {
    algorithm: "Ed25519-QUORUM-3-OF-5" as const,
    quorum: 3 as const,
    memberCount: 5 as const,
    decisionDigest: digestFor(decision),
    signatures: [signature, signature, signature],
  };

  const result = verifyGovernanceQuorumCertificate(
    decision,
    certificate,
    members.map(({ member }) => member),
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_QUORUM_DUPLICATE_SIGNER",
  );
});

test("decision mutation invalidates the quorum", () => {
  const { members, decision } = fixture();

  const certificate = createGovernanceQuorumCertificate(
    decision,
    members,
  );

  const mutatedDecision = {
    ...decision,
    target: "TAMPERED_TARGET",
  };

  const result = verifyGovernanceQuorumCertificate(
    mutatedDecision,
    certificate,
    members.map(({ member }) => member),
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_QUORUM_DECISION_DIGEST_MISMATCH",
  );
});

test("unauthorized signer is rejected", () => {
  const { members, decision } = fixture();

  const outsider = generateGovernanceQuorumMember(
    "outsider",
  );

  const signatures = [
    ...members.slice(0, 2).map((member) =>
      signGovernanceQuorumMember(decision, member),
    ),
    signGovernanceQuorumMember(decision, outsider),
  ];

  const certificate = {
    algorithm: "Ed25519-QUORUM-3-OF-5" as const,
    quorum: 3 as const,
    memberCount: 5 as const,
    decisionDigest: digestFor(decision),
    signatures,
  };

  const result = verifyGovernanceQuorumCertificate(
    decision,
    certificate,
    members.map(({ member }) => member),
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_QUORUM_SIGNER_NOT_REGISTERED",
  );
});

test("revoked signer cannot satisfy quorum", () => {
  const { members, decision } = fixture();

  const certificate = createGovernanceQuorumCertificate(
    decision,
    members,
  );

  const registered = members.map(({ member }) => member);

  registered[0] = {
    memberId: registered[0]!.memberId,
    purpose: registered[0]!.purpose,
    publicKeyPem: registered[0]!.publicKeyPem,
    status: "revoked",
  };

  const result = verifyGovernanceQuorumCertificate(
    decision,
    certificate,
    registered,
  );

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GOVERNANCE_QUORUM_SIGNER_NOT_ACTIVE",
  );
});

function digestFor(decision: unknown): string {
  return governanceDecisionDigest(decision);
}
