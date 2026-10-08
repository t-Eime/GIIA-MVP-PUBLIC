import test from "node:test";
import assert from "node:assert/strict";
import { evaluateActionGate } from "../../src/action-gate/service.js";
import type { ActionGateInput } from "../../src/action-gate/types.js";
import type { GovernorResult } from "../../src/governor/types.js";
import type { GuardianResult } from "../../src/guardian/types.js";
import { evaluateGovernor } from "../../src/governor/service.js";
import { evaluateGuardian } from "../../src/guardian/service.js";
import { verifyInstitutionalIntegrity } from "../../src/attestation/service.js";
import type { ComponentAttestation } from "../../src/attestation/types.js";

const NOW = "2026-10-02T12:00:00.000Z";

function governor(): GovernorResult {
  return {
    organ: "GOVERNOR",
    decision: "ALLOW",
    reason: "GOVERNOR_PIPELINE_LEGITIMACY_VERIFIED",
    requestId: "req-1",
    actorId: "actor-1",
    action: "TRANSFER",
    target: "account-1",
    issuedAt: NOW,
    authoritative: true,
    source: "AUTHORITATIVE_GIIA_PIPELINE",
  };
}

function guardian(): GuardianResult {
  return {
    organ: "GUARDIAN",
    decision: "ALLOW",
    reason: "GUARDIAN_PIPELINE_SAFETY_BOUNDARY_VERIFIED",
    requestId: "req-1",
    actorId: "actor-1",
    action: "TRANSFER",
    target: "account-1",
    issuedAt: NOW,
    authoritative: true,
    source: "AUTHORITATIVE_GIIA_PIPELINE",
  };
}

function attestation(
  componentId: string,
  componentType: "GOVERNOR" | "GUARDIAN",
): ComponentAttestation {
  return {
    attestationId: `att-${componentType.toLowerCase()}`,
    componentId,
    componentType,
    measurement: {
      componentId,
      componentType,
      implementationVersion: "1.0.0",
      measurement: `measurement-${componentType.toLowerCase()}`,
      environmentBinding: "env-1",
      policyVersion: "policy-1",
      constitutionVersion: "constitution-1",
    },
    issuedAt: "2026-10-02T11:00:00.000Z",
    expiresAt: "2026-10-02T13:00:00.000Z",
    nonce: `nonce-${componentType.toLowerCase()}`,
    issuerId: "independent-attestation-root",
    revoked: false,
    signatureValid: true,
  };
}

function integrity(
  componentId: string,
  componentType: "GOVERNOR" | "GUARDIAN",
) {
  return verifyInstitutionalIntegrity(
    attestation(componentId, componentType),
    {
      expectedComponentId: componentId,
      expectedComponentType: componentType,
      expectedImplementationVersion: "1.0.0",
      expectedMeasurement: `measurement-${componentType.toLowerCase()}`,
      expectedEnvironmentBinding: "env-1",
      expectedPolicyVersion: "policy-1",
      expectedConstitutionVersion: "constitution-1",
      nonce: `nonce-${componentType.toLowerCase()}`,
      at: NOW,
    },
  );
}

function base(): ActionGateInput {
  return {
    governor: governor(),
    guardian: guardian(),
    governorIntegrity: integrity("governor-1", "GOVERNOR"),
    guardianIntegrity: integrity("guardian-1", "GUARDIAN"),
    evidenceValid: true,
    authorityValid: true,
    constitutionAllows: true,
    conditionsValid: true,
    noUnresolvedConflict: true,
    enforcementHealthy: true,
    exactActionBound: true,
    actionNotAlreadyExecuted: true,
    criticalTrustRootsHealthy: true,
  };
}

test("standalone Governor assessment cannot enter the execution gate", () => {
  const input = base();

  const result = evaluateActionGate({
    ...input,
    governor: {
      ...input.governor,
      authoritative: false,
      source: "ORGAN_ASSESSMENT",
    } as never,
  });

  assert.equal(result.decision, "BLOCK");
  assert.equal(
    result.reason,
    "GOVERNOR_NOT_AUTHORITATIVE_PIPELINE_RESULT",
  );
});

test("standalone Guardian assessment cannot enter the execution gate", () => {
  const input = base();

  const result = evaluateActionGate({
    ...input,
    guardian: {
      ...input.guardian,
      authoritative: false,
      source: "ORGAN_ASSESSMENT",
    } as never,
  });

  assert.equal(result.decision, "BLOCK");
  assert.equal(
    result.reason,
    "GUARDIAN_NOT_AUTHORITATIVE_PIPELINE_RESULT",
  );
});

test("both organs plus all controls permit execution", () => {
  const result = evaluateActionGate(base());

  assert.equal(result.decision, "ALLOW_EXECUTION");
  assert.equal(result.executable, true);
});

test("Governor DENY blocks execution", () => {
  const input = base();

  const result = evaluateActionGate({
    ...input,
    governor: {
      ...input.governor,
      decision: "DENY",
      reason: "test",
    },
  });

  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reason, "GOVERNOR_NOT_ALLOW");
});

test("Guardian DENY blocks execution", () => {
  const input = base();

  const result = evaluateActionGate({
    ...input,
    guardian: {
      ...input.guardian,
      decision: "DENY",
      reason: "test",
    },
  });

  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reason, "GUARDIAN_NOT_ALLOW");
});

test("valid Governor credential cannot bypass failed institutional attestation", () => {
  const input = base();

  const result = evaluateActionGate({
    ...input,
    governorIntegrity: {
      ...input.governorIntegrity,
      status: "INVALID",
      verified: false,
      reason: "ATTESTATION_MEASUREMENT_MISMATCH",
    },
  });

  assert.equal(result.decision, "BLOCK");
  assert.equal(
    result.reason,
    "GOVERNOR_INSTITUTIONAL_INTEGRITY_NOT_VERIFIED",
  );
});

test("valid Guardian credential cannot bypass failed institutional attestation", () => {
  const input = base();

  const result = evaluateActionGate({
    ...input,
    guardianIntegrity: {
      ...input.guardianIntegrity,
      status: "INVALID",
      verified: false,
      reason: "ATTESTATION_MEASUREMENT_MISMATCH",
    },
  });

  assert.equal(result.decision, "BLOCK");
  assert.equal(
    result.reason,
    "GUARDIAN_INSTITUTIONAL_INTEGRITY_NOT_VERIFIED",
  );
});

test("unknown integrity never becomes execution permission", () => {
  const input = base();

  const result = evaluateActionGate({
    ...input,
    governorIntegrity: {
      ...input.governorIntegrity,
      status: "UNKNOWN",
      verified: false,
    },
  });

  assert.equal(result.decision, "BLOCK");
});

test("expired attestation cannot produce execution permission", () => {
  const expired = verifyInstitutionalIntegrity(
    {
      ...attestation("governor-1", "GOVERNOR"),
      expiresAt: "2026-10-02T11:59:59.000Z",
    },
    {
      expectedComponentId: "governor-1",
      expectedComponentType: "GOVERNOR",
      expectedImplementationVersion: "1.0.0",
      expectedMeasurement: "measurement-governor",
      expectedEnvironmentBinding: "env-1",
      expectedPolicyVersion: "policy-1",
      expectedConstitutionVersion: "constitution-1",
      nonce: "nonce-governor",
      at: NOW,
    },
  );

  assert.equal(expired.verified, false);
  assert.equal(expired.status, "EXPIRED");
});

test("Governor and Guardian cannot independently manufacture execution", () => {
  const g = governor();
  const h = guardian();

  assert.equal(g.decision, "ALLOW");
  assert.equal(h.decision, "ALLOW");

  const input = base();

  const result = evaluateActionGate({
    ...input,
    enforcementHealthy: false,
  });

  assert.equal(result.decision, "BLOCK");
  assert.equal(result.executable, false);
});

test("critical trust-root compromise blocks even unanimous approval", () => {
  const input = base();

  const result = evaluateActionGate({
    ...input,
    criticalTrustRootsHealthy: false,
  });

  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reason, "CRITICAL_TRUST_ROOT_COMPROMISED");
});
