import assert from "node:assert/strict";
import test from "node:test";

import { createMvpComposition } from "../../src/mvp/composition.js";
import { verifyDecisionRecord } from "../../src/mvp/verification.js";
import {
  generateGovernanceAuthorityMember,
  createGovernanceAuthoritySet,
} from "../../src/security/governance-authority.js";

test("MVP decision independently verifies", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "verify-001",
      action: "read",
      resource: "resource-001",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);

    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const verification = verifyDecisionRecord(record);

    assert.equal(verification.valid, true);
    assert.equal(
      verification.reason,
      "DECISION_RECORD_VERIFIED",
    );
  } finally {
    composition.close();
  }
});

test("tampered decision is independently rejected", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "verify-002",
      action: "read",
      resource: "resource-001",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);

    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const tampered = {
      ...record,
      decision:
        record.decision === "ALLOW"
          ? "DENY"
          : "ALLOW",
    };

    const verification =
      verifyDecisionRecord(tampered);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("execution authority cannot be forged into a valid record", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "verify-003",
      action: "read",
      resource: "resource-001",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);

    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const forged = {
      ...record,
      executionPermitted: true,
    };

    const verification =
      verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: authoritative decision contains a valid 3-of-5 governance certificate", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-001",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);

    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    assert.equal(
      record.governanceAuthorityCertificate.algorithm,
      "ED25519-MULTISIG-3-OF-5",
    );

    assert.equal(
      record.governanceAuthorityCertificate.signatures.length,
      3,
    );

    const verification = verifyDecisionRecord(record);

    assert.equal(verification.valid, true);
    assert.equal(
      verification.reason,
      "DECISION_RECORD_VERIFIED",
    );
  } finally {
    composition.close();
  }
});

test("P0-A: one authority member cannot authorize an authoritative decision", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-002",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const forged = {
      ...record,
      governanceAuthorityCertificate: {
        ...record.governanceAuthorityCertificate,
        signatures:
          record.governanceAuthorityCertificate.signatures.slice(
            0,
            1,
          ),
      },
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: two authority members cannot authorize an authoritative decision", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-003",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const forged = {
      ...record,
      governanceAuthorityCertificate: {
        ...record.governanceAuthorityCertificate,
        signatures:
          record.governanceAuthorityCertificate.signatures.slice(
            0,
            2,
          ),
      },
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: duplicate authority signer is rejected", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-004",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const signatures =
      record.governanceAuthorityCertificate.signatures;

    const forged = {
      ...record,
      governanceAuthorityCertificate: {
        ...record.governanceAuthorityCertificate,
        signatures: [
          ...signatures.slice(0, 2),
          signatures[0],
        ],
      },
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: revoked authority signer is rejected", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-005",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const firstSignature =
      record.governanceAuthorityCertificate.signatures[0];

    assert.ok(firstSignature);

    const firstSignerId =
      firstSignature.memberId;

    const modifiedMembers =
      record.governanceAuthoritySet.members.map(
        (member) =>
          member.memberId === firstSignerId
            ? {
                ...member,
                status: "revoked" as const,
              }
            : member,
      );

    const forgedAuthoritySet = {
      ...record.governanceAuthoritySet,
      members: modifiedMembers,
    };

    const forged = {
      ...record,
      governanceAuthoritySet: forgedAuthoritySet,
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: quarantined authority signer is rejected", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-006",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const firstSignature =
      record.governanceAuthorityCertificate.signatures[0];

    assert.ok(firstSignature);

    const firstSignerId =
      firstSignature.memberId;

    const modifiedMembers =
      record.governanceAuthoritySet.members.map(
        (member) =>
          member.memberId === firstSignerId
            ? {
                ...member,
                status: "quarantined" as const,
              }
            : member,
      );

    const forged = {
      ...record,
      governanceAuthoritySet: {
        ...record.governanceAuthoritySet,
        members: modifiedMembers,
      },
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: expired authority signer is rejected", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-007",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const firstSignature =
      record.governanceAuthorityCertificate.signatures[0];

    assert.ok(firstSignature);

    const firstSignerId =
      firstSignature.memberId;

    const modifiedMembers =
      record.governanceAuthoritySet.members.map(
        (member) =>
          member.memberId === firstSignerId
            ? {
                ...member,
                status: "expired" as const,
              }
            : member,
      );

    const forged = {
      ...record,
      governanceAuthoritySet: {
        ...record.governanceAuthoritySet,
        members: modifiedMembers,
      },
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: certificate mutation is rejected", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-008",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const forged = {
      ...record,
      governanceAuthorityCertificate: {
        ...record.governanceAuthorityCertificate,
        decisionDigest:
          record.governanceAuthorityCertificate
            .decisionDigest ===
          "00".repeat(32)
            ? "11".repeat(32)
            : "00".repeat(32),
      },
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: removing the governance certificate is rejected", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-009",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const {
      governanceAuthorityCertificate,
      ...withoutCertificate
    } = record;

    void governanceAuthorityCertificate;

    const verification = verifyDecisionRecord(
      withoutCertificate as typeof record,
    );

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: decision mutation remains rejected despite a valid certificate", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-010",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const forged = {
      ...record,
      action:
        record.action === "read"
          ? "delete"
          : "read",
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: wrong governance authority set is rejected", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-011",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const members = Array.from(
      { length: 5 },
      (_, index) =>
        generateGovernanceAuthorityMember(
          `wrong-authority-member-${index + 1}`,
        ),
    );

    const wrongAuthoritySet =
      createGovernanceAuthoritySet(
        "wrong-authority-set",
        1,
          members.map((member) => member.member),
      );

    const forged = {
      ...record,
      governanceAuthoritySet: wrongAuthoritySet,
    };

    const verification = verifyDecisionRecord(forged);

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});

test("P0-A: legacy single-key signature without the authority certificate is insufficient", () => {
  const composition = createMvpComposition();

  try {
    const input = {
      requestId: "p0a-012",
      action: "read",
      resource: "resource-p0a",
      requestedAt: "2026-10-04T10:00:00.000Z",
    };

    const result = composition.evaluate(input);
    const record = composition.createDecisionRecord(
      result,
      input.requestId,
      input.action,
      input.resource,
      input.requestedAt,
    );

    const {
      governanceAuthorityCertificate,
      ...legacyRecord
    } = record;

    void governanceAuthorityCertificate;

    const verification = verifyDecisionRecord(
      legacyRecord as typeof record,
    );

    assert.equal(verification.valid, false);
  } finally {
    composition.close();
  }
});
