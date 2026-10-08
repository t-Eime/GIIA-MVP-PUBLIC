import assert from "node:assert/strict";
import test from "node:test";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";

import {
  createMvpComposition,
} from "../../src/mvp/composition.js";

import {
  verifyDecisionRecordSignature,
} from "../../src/mvp/decision-record.js";

import {
  projectMvpDecisionForEnforcement,
} from "../../src/enforcement/mvp-decision-bridge.js";

import {
  createGovernanceAuthoritySet,
  generateGovernanceAuthorityMember,
} from "../../src/security/governance-authority.js";

import {
  createAgentPassport,
} from "../../src/identity/agent-passport.js";

import {
  executeExternally,
} from "../../external-mvp/executor.js";

import {
  MemoryExternalReplayStore,
} from "../../external-mvp/replay-store.js";

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }

  const record = value as Record<string, unknown>;

  return `{${Object.keys(record)
    .sort()
    .map(
      key =>
        `${JSON.stringify(key)}:${canonical(record[key])}`,
    )
    .join(",")}}`;
}

function hash(value: unknown): string {
  return createHash("sha256")
    .update(canonical(value), "utf8")
    .digest("hex");
}

function makeP0BAttackerAuthoritySet() {
  const members = Array.from(
    { length: 5 },
    (_, index) =>
      generateGovernanceAuthorityMember(
        `p0b-attacker-member-${index + 1}`,
      ).member,
  );

  return createGovernanceAuthoritySet(
    "p0b-attacker-authority-set",
    1,
    members,
  );
}

function fixture() {
  const composition = createMvpComposition();

  const input = {
    requestId: "e2e-enforcement-001",
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

  const payload = {
    requestId: input.requestId,
    action: input.action,
    resource: input.resource,
  };

  const passportKeys = generateKeyPairSync("ed25519");
  const executorKeys = generateKeyPairSync("ed25519");

  const passport = createAgentPassport(
    {
      agentId: "external-mvp-executor",
      passportId: "passport-e2e-executor",
      issuerId: "issuer-mvp",
      origin: "giia-mvp",
      jurisdiction: "NG",
      operatorId: "operator-mvp",
      ownerId: "owner-mvp",
      agentType: "governed-agent",
      modelType: "mvp-executor",
      lifecycle: "production",
      deploymentEnvironment: "controlled",
      declaredCapabilities: ["read"],
      permittedCapabilities: ["read"],
      credentialIds: ["credential-mvp"],
      delegationIds: ["delegation-mvp"],
      issuedAt: "2026-09-01T00:00:00.000Z",
      expiresAt: "2027-01-01T00:00:00.000Z",
      publicKeyPem: passportKeys.publicKey.export({
        type: "spki",
        format: "pem",
      }) as string,
    },
    passportKeys.privateKey,
  );

  /*
   * P0-C: the independent executor pins the legitimate
   * governance authority trust root. The decision record
   * does not establish that root.
   */
  const trustedAuthoritySet =
    record.governanceAuthoritySet;

  const decision = projectMvpDecisionForEnforcement(
    record,
    {
      humanApprovalRequired: false,
      humanApprovalVerified: false,
      revocationState: "active",
      shutdownState: "clear",
    },
    trustedAuthoritySet,
  );

  const authorizationBase = {
    authorizationId: "e2e-external-auth-001",
    executorId: "external-mvp-executor",
    decisionId: decision.decisionId,
    requestId: decision.requestId,
    actorId: decision.actorId,
    passportId: passport.passportId,
    action: decision.action,
    target: decision.target,
    payloadHash: decision.payloadHash,
    constitutionVersion:
      decision.constitutionVersion,
    nonce: decision.nonce,
    issuedAt: decision.issuedAt,
    expiresAt: decision.expiresAt,
    signingAlgorithm: "Ed25519" as const,
    publicKeyPem: executorKeys.publicKey.export({
      type: "spki",
      format: "pem",
    }) as string,
  };

  const authorization = {
    ...authorizationBase,
    signatureBase64: sign(
      null,
      Buffer.from(
        canonical(authorizationBase),
        "utf8",
      ),
      executorKeys.privateKey,
    ).toString("base64"),
  };

  return {
    composition,
    record,
    decision,
    passport,
    authorization,
    payload,
  };
}

test(
  "P0-B: executor rejects substituted authority set",
  () => {
    const f = fixture();

    try {
      const attackerSet = makeP0BAttackerAuthoritySet();

      const substituted = {
        ...f.record,
        governanceAuthoritySet: attackerSet,
      };

      assert.throws(
        () =>
          projectMvpDecisionForEnforcement(
            substituted,
            {
              humanApprovalRequired: false,
              humanApprovalVerified: false,
              revocationState: "active",
              shutdownState: "clear",
            },
            f.record.governanceAuthoritySet,
          ),
        /MVP_GOVERNANCE_AUTHORITY_TRUST_ROOT_INVALID/,
      );
    } finally {
      f.composition.close();
    }
  },
);

test(
  "P0-B: executor rejects substituted authority fingerprint",
  () => {
    const f = fixture();

    try {
      const attackerSet = makeP0BAttackerAuthoritySet();

      const substituted = {
        ...f.record,
        governanceAuthoritySet: {
          ...f.record.governanceAuthoritySet,
          fingerprint: attackerSet.fingerprint,
        },
      };

      assert.throws(
        () =>
          projectMvpDecisionForEnforcement(
            substituted,
            {
              humanApprovalRequired: false,
              humanApprovalVerified: false,
              revocationState: "active",
              shutdownState: "clear",
            },
            f.record.governanceAuthoritySet,
          ),
        /MVP_GOVERNANCE_AUTHORITY_SET_NOT_PINNED|MVP_GOVERNANCE_AUTHORITY_TRUST_ROOT_INVALID/,
      );
    } finally {
      f.composition.close();
    }
  },
);

test(
  "P0-B: executor rejects substituted authority member key",
  () => {
    const f = fixture();

    try {
      const attackerMember =
        generateGovernanceAuthorityMember(
          "p0b-attacker-member-key",
        ).member;

      const substitutedMembers = [
        attackerMember,
        ...f.record.governanceAuthoritySet.members.slice(1),
      ];

      const substituted = {
        ...f.record,
        governanceAuthoritySet: {
          ...f.record.governanceAuthoritySet,
          members: substitutedMembers,
        },
      };

      assert.throws(
        () =>
          projectMvpDecisionForEnforcement(
            substituted,
            {
              humanApprovalRequired: false,
              humanApprovalVerified: false,
              revocationState: "active",
              shutdownState: "clear",
            },
            f.record.governanceAuthoritySet,
          ),
        /MVP_GOVERNANCE_AUTHORITY_TRUST_ROOT_INVALID|MVP_GOVERNANCE_AUTHORITY_SET_NOT_PINNED/,
      );
    } finally {
      f.composition.close();
    }
  },
);

test(
  "real signed GIIA decision reaches independent external executor",
  () => {
    const f = fixture();

    try {
      assert.equal(
        verifyDecisionRecordSignature(f.record),
        true,
      );

      assert.equal(
        f.record.executionPermitted,
        false,
      );

      assert.equal(
        f.record.executionBinding.actorId,
        "mvp-identity-001",
      );

      assert.equal(
        f.decision.actorId,
        "mvp-identity-001",
      );

      assert.equal(
        f.decision.target,
        "resource-001",
      );

      const result = executeExternally({
        decision: f.decision,
        authorization: f.authorization,
        passport: f.passport,
        payload: f.payload,
        capability: "read",
        at: "2026-10-04T10:01:00.000Z",
        replayStore: new MemoryExternalReplayStore(),
      });

      assert.equal(result.executed, true);
      assert.equal(
        result.reason,
        "EXTERNAL_ACTION_EXECUTED",
      );
      assert.ok(result.evidence);
    } finally {
      f.composition.close();
    }
  },
);

test(
  "tampering with the signed GIIA decision blocks external enforcement",
  () => {
    const f = fixture();

    try {
      const tampered = {
        ...f.record,
        action: "delete",
      };

      assert.equal(
        verifyDecisionRecordSignature(tampered),
        false,
      );

      assert.throws(
        () =>
          projectMvpDecisionForEnforcement(
            tampered,
            {
              humanApprovalRequired: false,
              humanApprovalVerified: false,
              revocationState: "active",
              shutdownState: "clear",
            },
            f.record.governanceAuthoritySet,
          ),
        /MVP_GOVERNANCE_AUTHORITY_TRUST_ROOT_INVALID:GOVERNANCE_AUTHORITY_DECISION_DIGEST_MISMATCH/
      );
    } finally {
      f.composition.close();
    }
  },
);

test(
  "tampering with the execution payload blocks external enforcement",
  () => {
    const f = fixture();

    try {
      const result = executeExternally({
        decision: f.decision,
        authorization: f.authorization,
        passport: f.passport,
        payload: {
          requestId: f.payload.requestId,
          action: f.payload.action,
          resource: "attacker-resource",
        },
        capability: "read",
        at: "2026-10-04T10:01:00.000Z",
      });

      assert.equal(result.executed, false);
      assert.equal(
        result.reason,
        "PAYLOAD_HASH_MISMATCH",
      );
      assert.equal(result.evidence, null);
    } finally {
      f.composition.close();
    }
  },
);

test(
  "binding the wrong executor passport blocks external enforcement",
  () => {
    const f = fixture();

    try {
      const wrongKeys =
        generateKeyPairSync("ed25519");

      const wrongPassport = createAgentPassport(
        {
          agentId: "attacker-executor",
          passportId: "attacker-passport",
          issuerId: "issuer-mvp",
          origin: "giia-mvp",
          jurisdiction: "NG",
          operatorId: "operator-mvp",
          ownerId: "owner-mvp",
          agentType: "governed-agent",
          modelType: "attacker",
          lifecycle: "production",
          deploymentEnvironment: "controlled",
          declaredCapabilities: ["read"],
          permittedCapabilities: ["read"],
          credentialIds: ["credential-mvp"],
          delegationIds: ["delegation-mvp"],
          issuedAt: "2026-09-01T00:00:00.000Z",
          expiresAt: "2027-01-01T00:00:00.000Z",
          publicKeyPem: wrongKeys.publicKey.export({
            type: "spki",
            format: "pem",
          }) as string,
        },
        wrongKeys.privateKey,
      );

      const result = executeExternally({
        decision: f.decision,
        authorization: f.authorization,
        passport: wrongPassport,
        payload: f.payload,
        capability: "read",
        at: "2026-10-04T10:01:00.000Z",
      });

      assert.equal(result.executed, false);
      assert.equal(
        result.reason,
        "AGENT_PASSPORT_BINDING_MISMATCH",
      );
      assert.equal(result.evidence, null);
    } finally {
      f.composition.close();
    }
  },
);
