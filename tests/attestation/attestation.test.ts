import test from "node:test";
import assert from "node:assert/strict";
import { verifyInstitutionalIntegrity } from "../../src/attestation/service.js";
import type { ComponentAttestation } from "../../src/attestation/types.js";

const base: ComponentAttestation = {
  attestationId: "att-1",
  componentId: "governor-1",
  componentType: "GOVERNOR",
  measurement: {
    componentId: "governor-1",
    componentType: "GOVERNOR",
    implementationVersion: "1.0.0",
    measurement: "measurement-1",
    environmentBinding: "env-1",
    policyVersion: "policy-1",
    constitutionVersion: "constitution-1",
  },
  issuedAt: "2026-10-02T11:00:00.000Z",
  expiresAt: "2026-10-02T13:00:00.000Z",
  nonce: "nonce-1",
  issuerId: "attestation-root",
  revoked: false,
  signatureValid: true,
};

const context = {
  expectedComponentId: "governor-1",
  expectedComponentType: "GOVERNOR" as const,
  expectedImplementationVersion: "1.0.0",
  expectedMeasurement: "measurement-1",
  expectedEnvironmentBinding: "env-1",
  expectedPolicyVersion: "policy-1",
  expectedConstitutionVersion: "constitution-1",
  nonce: "nonce-1",
  at: "2026-10-02T12:00:00.000Z",
};

test("valid attestation verifies institutional integrity", () => {
  const result = verifyInstitutionalIntegrity(base, context);

  assert.equal(result.verified, true);
  assert.equal(result.status, "VERIFIED");
});

test("measurement mismatch fails closed", () => {
  const result = verifyInstitutionalIntegrity(
    {
      ...base,
      measurement: {
        ...base.measurement,
        measurement: "tampered",
      },
    },
    context,
  );

  assert.equal(result.verified, false);
  assert.equal(result.status, "INVALID");
});

test("revoked attestation fails closed", () => {
  const result = verifyInstitutionalIntegrity(
    { ...base, revoked: true },
    context,
  );

  assert.equal(result.verified, false);
  assert.equal(result.status, "REVOKED");
});

test("invalid signature fails closed", () => {
  const result = verifyInstitutionalIntegrity(
    { ...base, signatureValid: false },
    context,
  );

  assert.equal(result.verified, false);
  assert.equal(result.status, "INVALID");
});
