import test from "node:test";
import assert from "node:assert/strict";
import { evaluateGuardian } from "../../src/guardian/service.js";

const common = {
  requestId: "r1",
  actorId: "a1",
  action: "TRANSFER",
  target: "t1",
  harmAcceptable: true,
  integrityConditionsValid: true,
  emergencyValid: true,
  resourceConditionsValid: true,
  anomalyResolved: true,
  evidenceValid: true,
  at: "2026-10-02T12:00:00.000Z",
};

test("Guardian allows a safe action", () => {
  assert.equal(evaluateGuardian(common).decision, "ALLOW");
});

test("Guardian contains integrity failure", () => {
  assert.equal(
    evaluateGuardian({
      ...common,
      integrityConditionsValid: false,
    }).decision,
    "CONTAIN",
  );
});

test("Guardian denies unacceptable harm", () => {
  assert.equal(
    evaluateGuardian({
      ...common,
      harmAcceptable: false,
    }).decision,
    "DENY",
  );
});

test("Guardian defers unresolved anomaly", () => {
  assert.equal(
    evaluateGuardian({
      ...common,
      anomalyResolved: false,
    }).decision,
    "DEFER",
  );
});
