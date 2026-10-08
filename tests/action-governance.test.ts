import test from "node:test";
import assert from "node:assert/strict";

import {
  assessHarmRisk,
  classifyAction,
} from "../src/action-governance/index.js";

test("known action is classified by governed rule", () => {
  const result = classifyAction("read");

  assert.equal(result.determined, true);
  assert.equal(result.classification, "READ");
  assert.equal(result.ruleId, "ac-v1-read");
  assert.equal(result.ruleVersion, "action-classification-v1");
});

test("unknown action does not receive a caller-controlled classification", () => {
  const result = classifyAction("ATTACKER_INVENTED_ACTION");

  assert.equal(result.determined, false);
  assert.equal(result.classification, null);
  assert.equal(result.ruleId, null);
});

test("empty action is rejected by classifier", () => {
  const result = classifyAction("   ");

  assert.equal(result.determined, false);
  assert.equal(result.classification, null);
  assert.equal(result.reason, "ACTION_EMPTY");
});

test("harm risk is derived from governed action class", () => {
  const result = assessHarmRisk(
    "read",
    "resource-001",
    "READ",
  );

  assert.equal(result.assessed, true);
  assert.equal(result.classification, "LOW");
  assert.equal(result.ruleId, "hr-v1-read");
  assert.equal(result.ruleVersion, "harm-risk-v1");
});

test("missing harm-risk rule fails closed to UNKNOWN", () => {
  const result = assessHarmRisk(
    "unknown",
    "resource-001",
    null,
  );

  assert.equal(result.assessed, false);
  assert.equal(result.classification, "UNKNOWN");
  assert.equal(result.ruleId, null);
});
