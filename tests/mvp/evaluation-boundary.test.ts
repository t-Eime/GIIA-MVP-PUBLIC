import assert from "node:assert/strict";
import test from "node:test";

import { createMvpComposition } from "../../src/mvp/composition.js";
import { verifyAuditIntegrity } from "../../src/audit/service.js";
import type { ActionIntent, ActionRecord } from "../../src/trust-action/types.js";

test("MVP evaluation creates ActionIntent, not execution ActionRecord", () => {
  const composition = createMvpComposition();

  try {
    const result = composition.evaluate({
      requestId: "mvp-boundary-001",
      action: "read",
      resource: "resource-001",
      requestedAt: "2026-10-04T10:00:00.000Z",
    });

    assert.ok(result.action);

    const action = result.action as ActionIntent;

    assert.equal(action.action, "read");
    assert.equal(action.resource, "resource-001");
    assert.equal(action.provenance, "giia-mvp-api");

    assert.equal(
      "executedAt" in action,
      false,
      "evaluation must not manufacture execution timestamp",
    );

    assert.equal(
      "outcome" in action,
      false,
      "evaluation must not manufacture execution outcome",
    );
  } finally {
    composition.close();
  }
});

test("MVP evaluation audit records EVALUATED, never EXECUTED", () => {
  const composition = createMvpComposition();

  try {
    const result = composition.evaluate({
      requestId: "mvp-boundary-002",
      action: "read",
      resource: "resource-001",
      requestedAt: "2026-10-04T10:00:00.000Z",
    });

    assert.ok(result.audit);
    assert.equal(result.audit.outcome, "EVALUATED");
    assert.notEqual(result.audit.outcome, "EXECUTED");
    assert.match(
      result.audit.reason,
      /no execution occurred/i,
    );
    assert.equal(
      verifyAuditIntegrity(result.audit),
      true,
    );
  } finally {
    composition.close();
  }
});

test("ActionRecord remains execution-only", () => {
  const intent: ActionIntent = {
    id: "intent-001",
    authorizationRequestId: "request-001",
    actor: "actor-001",
    action: "read",
    resource: "resource-001",
    provenance: "test",
  };

  const record: ActionRecord = {
    ...intent,
    executedAt: "2026-10-04T10:00:00.000Z",
    outcome: "SUCCESS",
  };

  assert.equal(record.executedAt, "2026-10-04T10:00:00.000Z");
  assert.equal(record.outcome, "SUCCESS");
});
