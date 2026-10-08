import assert from "node:assert/strict";
import test from "node:test";

import {
  validateDecisionRecord,
  validateEvaluateRequest,
} from "../../src/mvp/validation.js";

test("evaluate schema rejects missing request id", () => {
  assert.throws(
    () =>
      validateEvaluateRequest({
        action: "read",
        resource: "resource-001",
      }),
    /INVALID_REQUEST_ID/,
  );
});

test("evaluate schema rejects empty action", () => {
  assert.throws(
    () =>
      validateEvaluateRequest({
        requestId: "security-001",
        action: "",
        resource: "resource-001",
      }),
    /INVALID_ACTION/,
  );
});

test("evaluate schema rejects future timestamps", () => {
  assert.throws(
    () =>
      validateEvaluateRequest({
        requestId: "security-002",
        action: "read",
        resource: "resource-001",
        requestedAt: "2999-01-01T00:00:00.000Z",
      }),
    /REQUESTED_AT_IN_FUTURE/,
  );
});

test("evaluate schema rejects stale timestamps", () => {
  const old = new Date(
    Date.now() - 48 * 60 * 60 * 1000,
  ).toISOString();

  assert.throws(
    () =>
      validateEvaluateRequest({
        requestId: "security-003",
        action: "read",
        resource: "resource-001",
        requestedAt: old,
      }),
    /REQUESTED_AT_TOO_OLD/,
  );
});

test("decision validation rejects execution authority", () => {
  assert.throws(
    () =>
      validateDecisionRecord({
        version: "1",
        recordType: "GIIA_AUTHORITATIVE_DECISION",
        requestId: "security-004",
        action: "read",
        resource: "resource-001",
        decision: "ALLOW",
        reason: "test",
        authoritative: true,
        executionPermitted: true,
        provenance: "test",
        issuedAt: "2026-10-04T10:00:00.000Z",
        signerKeyId: "test",
        signerPublicKeyPem: "test",
        signature: "test",
      }),
    /EXECUTION_AUTHORITY_FORBIDDEN/,
  );
});
