import test from "node:test";
import assert from "node:assert/strict";

import { runOnce } from "../../src/runtime/runtime.js";
import { governObservation } from "../../src/runtime/governed.js";

function freshGoverned() {
  const runtime = runOnce();

  assert.equal(
    runtime.chain.valid,
    true,
    "phone observation chain must be valid",
  );

  const observation = runtime.observation;

  const intent = {
    actionId: "CREATE_GOVERNED_RECORD",
    target: `enforcement:${observation.observationId}`,
    payload: {
      observationHash: observation.contentHash,
      chainHead: runtime.chain.head,
    },
  };

  const governed = governObservation(
    {
      id: observation.observationId,
      observedAt: observation.timestamp,
      observationHash: observation.contentHash,
      device: observation.device,
      filesystem: observation.filesystem,
      network: observation.network,
      processes: observation.processes,
    },
    intent,
  );

  return { runtime, observation, intent, governed };
}

test("PHONE-01 valid governance produces ALLOW but no execution capability", () => {
  const { governed } = freshGoverned();

  assert.equal(governed.decision, "ALLOW");
  assert.equal(governed.authoritative, true);
  assert.equal(governed.trustValid, true);

  assert.equal(
    governed.executionCapability,
    null,
    "GIIA must not mint an execution capability",
  );
});

test("PHONE-02 autonomous execution is blocked even after ALLOW", () => {
  const { governed, intent } = freshGoverned();

  assert.throws(
    () =>
    /EXTERNAL_EXECUTOR_REQUIRED/,
  );
});

test("PHONE-03 governance remains separate from execution", () => {
  const { governed } = freshGoverned();

  assert.equal(governed.decision, "ALLOW");
  assert.equal(governed.executionCapability, null);
});

test("PHONE-04 denied governance cannot be executed", () => {
  const { governed, intent } = freshGoverned();

  const denied = {
    ...governed,
    decision: "DENY",
    authoritative: false,
  };

  assert.throws(
    () =>
    /EXTERNAL_EXECUTOR_REQUIRED/,
  );
});

test("PHONE-05 agent cannot obtain execution authority from prior ALLOW", () => {
  const { governed, intent } = freshGoverned();

  const forgedContinuation = {
    requestId: governed.requestId,
    decision: "ALLOW",
    authoritative: true,
    executionCapability: {
      forged: true,
      derivedFromPreviousSuccess: true,
    },
  };

  assert.throws(
    () =>
    /EXTERNAL_EXECUTOR_REQUIRED/,
  );
});
