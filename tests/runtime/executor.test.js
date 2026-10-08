import test from "node:test";
import assert from "node:assert/strict";

import {
  REGISTERED_ACTIONS,
  requestExternalEnforcement,
  verifyExternalExecutionEvidence,
} from "../../src/runtime/executor.js";

test("GIIA has no registered autonomous execution actions", () => {
  assert.deepEqual(REGISTERED_ACTIONS, []);
});

test("autonomous execution fails closed", () => {
  assert.throws(
    () =>
      requestExternalEnforcement({
        decision: "ALLOW",
        actionId: "ANY_ACTION",
        target: "ANY_TARGET",
      }),
    /GIIA_EXECUTOR_FAIL_CLOSED: EXTERNAL_EXECUTOR_REQUIRED/,
  );
});

test("governance ALLOW cannot directly become execution", () => {
  assert.throws(
    () =>
      requestExternalEnforcement({
        decision: "ALLOW",
        authoritative: true,
        governanceDecision: "ALLOW",
        authorizationDecision: "ALLOW",
      }),
    /EXTERNAL_EXECUTOR_REQUIRED/,
  );
});

test("execution-chain verification remains fail closed", () => {
  const result = verifyExternalExecutionEvidence();

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "GIIA_EXECUTOR_DISABLED_EXTERNAL_BOUNDARY_REQUIRED",
  );
});
