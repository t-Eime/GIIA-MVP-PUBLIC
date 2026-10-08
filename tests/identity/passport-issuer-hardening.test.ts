import test from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPairSync,
} from "node:crypto";

import {
  createIssuerSignedAgentPassport,
  verifyAgentPassportWithIssuer,
  passportAllowsCapability,
} from "../../src/identity/agent-passport.js";

import {
  InMemoryPassportIssuerRegistry,
} from "../../src/identity/passport-issuer-registry.js";

function fixture() {
  const agent = generateKeyPairSync("ed25519");
  const issuer = generateKeyPairSync("ed25519");
  const attacker = generateKeyPairSync("ed25519");

  const issuerId = "giia-passport-issuer-001";
  const issuerKeyId = "giia-passport-key-001";

  const registry =
    new InMemoryPassportIssuerRegistry();

  registry.registerIssuer({
    issuerId,
    issuerKeyId,
    jurisdiction: "NG",
    purpose: "agent-passport-issuer",
    provenance: "test",
    publicKeyPem: issuer.publicKey.export({
      type: "spki",
      format: "pem",
    }).toString(),
    status: "ACTIVE",
  });

  const passport =
    createIssuerSignedAgentPassport(
      {
        passportId: "passport-001",
        agentId: "agent-001",
        issuerId,
        origin: "GIIA",
        jurisdiction: "NG",
        operatorId: "operator-001",
        ownerId: "owner-001",
        agentType: "governed-agent",
        modelType: "test-model",
        lifecycle: "production",
        deploymentEnvironment: "sandbox",
        declaredCapabilities: [
          "READ",
          "EXECUTE",
        ],
        permittedCapabilities: [
          "READ",
          "EXECUTE",
        ],
        credentialIds: [],
        delegationIds: [],
        issuedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2027-01-01T00:00:00.000Z",
        publicKeyPem: agent.publicKey.export({
          type: "spki",
          format: "pem",
        }).toString(),
      },
      agent.privateKey,
      issuerKeyId,
      issuer.privateKey,
    );

  return {
    agent,
    issuer,
    attacker,
    registry,
    passport,
    issuerId,
    issuerKeyId,
  };
}

test(
  "trusted issuer plus valid agent signature passes",
  () => {
    const f = fixture();

    const result =
      verifyAgentPassportWithIssuer(
        f.passport,
        "2026-06-01T00:00:00.000Z",
        f.registry,
      );

    assert.equal(result.valid, true);
    assert.equal(
      result.reason,
      "PASSPORT_VALID_WITH_TRUSTED_ISSUER",
    );
  },
);

test(
  "self-signed passport without issuer proof is denied",
  () => {
    const f = fixture();

    const {
      issuerSignatureBase64: _issuerSignature,
      ...forged
    } = f.passport;

    const result =
      verifyAgentPassportWithIssuer(
        forged,
        "2026-06-01T00:00:00.000Z",
        f.registry,
      );

    assert.equal(result.valid, false);
    assert.equal(
      result.reason,
      "ISSUER_SIGNATURE_REQUIRED",
    );
  },
);

test(
  "unknown issuer is denied",
  () => {
    const f = fixture();

    const forged = {
      ...f.passport,
      issuerId: "attacker-issuer",
    };

    const result =
      verifyAgentPassportWithIssuer(
        forged,
        "2026-06-01T00:00:00.000Z",
        f.registry,
      );

    assert.equal(result.valid, false);
    assert.equal(
      result.reason,
      "PASSPORT_ISSUER_UNKNOWN",
    );
  },
);

test(
  "revoked issuer is denied",
  () => {
    const f = fixture();

    f.registry.registerIssuer({
      issuerId: "revoked-issuer",
      issuerKeyId: "revoked-key",
      jurisdiction: "NG",
      purpose: "agent-passport-issuer",
      provenance: "test",
      publicKeyPem:
        f.issuer.publicKey.export({
          type: "spki",
          format: "pem",
        }).toString(),
      status: "REVOKED",
    });

    const forged = {
      ...f.passport,
      issuerId: "revoked-issuer",
      issuerKeyId: "revoked-key",
    };

    const result =
      verifyAgentPassportWithIssuer(
        forged,
        "2026-06-01T00:00:00.000Z",
        f.registry,
      );

    assert.equal(result.valid, false);
    assert.equal(
      result.reason,
      "PASSPORT_ISSUER_NOT_ACTIVE",
    );
  },
);

test(
  "wrong issuer key is denied",
  () => {
    const f = fixture();

    const other =
      generateKeyPairSync("ed25519");

    f.registry.registerIssuer({
      issuerId: "other-issuer",
      issuerKeyId: "other-key",
      jurisdiction: "NG",
      purpose: "agent-passport-issuer",
      provenance: "test",
      publicKeyPem:
        other.publicKey.export({
          type: "spki",
          format: "pem",
        }).toString(),
      status: "ACTIVE",
    });

    const forged = {
      ...f.passport,
      issuerId: "other-issuer",
      issuerKeyId: "other-key",
    };

    const result =
      verifyAgentPassportWithIssuer(
        forged,
        "2026-06-01T00:00:00.000Z",
        f.registry,
      );

    assert.equal(result.valid, false);
    assert.equal(
      result.reason,
      "PASSPORT_ISSUER_SIGNATURE_INVALID",
    );
  },
);

test(
  "passport modification after issuer signing is denied",
  () => {
    const f = fixture();

    const forged = {
      ...f.passport,
      declaredCapabilities: [
        ...f.passport.declaredCapabilities,
        "ADMIN",
      ],
      permittedCapabilities: [
        ...f.passport.permittedCapabilities,
        "ADMIN",
      ],
    };

    const result =
      verifyAgentPassportWithIssuer(
        forged,
        "2026-06-01T00:00:00.000Z",
        f.registry,
      );

    assert.equal(result.valid, false);
    assert.equal(
      result.reason,
      "PASSPORT_ISSUER_SIGNATURE_INVALID",
    );
  },
);

test(
  "issuer cannot silently substitute the agent public key",
  () => {
    const f = fixture();

    const attackerPassport = {
      ...f.passport,
      publicKeyPem:
        f.attacker.publicKey.export({
          type: "spki",
          format: "pem",
        }).toString(),
    };

    const result =
      verifyAgentPassportWithIssuer(
        attackerPassport,
        "2026-06-01T00:00:00.000Z",
        f.registry,
      );

    assert.equal(result.valid, false);
  },
);

test(
  "issuer validity window is enforced",
  () => {
    const f = fixture();

    const registry =
      new InMemoryPassportIssuerRegistry();

    registry.registerIssuer({
      issuerId: f.issuerId,
      issuerKeyId: f.issuerKeyId,
      jurisdiction: "NG",
      purpose: "agent-passport-issuer",
      provenance: "test",
      publicKeyPem:
        f.issuer.publicKey.export({
          type: "spki",
          format: "pem",
        }).toString(),
      status: "ACTIVE",
      notBefore: "2026-07-01T00:00:00.000Z",
      notAfter: "2026-08-01T00:00:00.000Z",
    });

    const result =
      verifyAgentPassportWithIssuer(
        f.passport,
        "2026-06-01T00:00:00.000Z",
        registry,
      );

    assert.equal(result.valid, false);
    assert.equal(
      result.reason,
      "PASSPORT_ISSUER_NOT_YET_VALID",
    );
  },
);

test(
  "capability requires both declaration and permission",
  () => {
    const f = fixture();

    assert.equal(
      passportAllowsCapability(
        f.passport,
        "EXECUTE",
      ),
      true,
    );

    assert.equal(
      passportAllowsCapability(
        {
          ...f.passport,
          permittedCapabilities: ["READ"],
        },
        "EXECUTE",
      ),
      false,
    );
  },
);
