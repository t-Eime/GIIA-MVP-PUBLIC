import test from "node:test";
import assert from "node:assert/strict";
import { evaluateGovernor } from "../../src/governor/service.js";

const common = {
  requestId: "r1",
  actorId: "a1",
  action: "TRANSFER",
  target: "t1",
  authorityValid: true,
  delegationValid: true,
  jurisdictionValid: true,
  policyAllows: true,
  constitutionAllows: true,
  prohibited: false,
  evidenceValid: true,
  at: "2026-10-02T12:00:00.000Z",
};

test("Governor allows a constitutionally valid action", () => {
  assert.equal(evaluateGovernor(common).decision, "ALLOW");
});

test("Governor denies invalid authority", () => {
  assert.equal(
    evaluateGovernor({ ...common, authorityValid: false }).decision,
    "DENY",
  );
});

test("Governor never allows prohibited action", () => {
  assert.equal(
    evaluateGovernor({ ...common, prohibited: true }).decision,
    "DENY",
  );
});

test("Governor defers when required evidence is insufficient", () => {
  assert.equal(
    evaluateGovernor({ ...common, evidenceValid: false }).decision,
    "DEFER",
  );
});
