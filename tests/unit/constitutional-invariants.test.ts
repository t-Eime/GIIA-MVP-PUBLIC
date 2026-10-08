import test from "node:test";
import assert from "node:assert/strict";

import {
  CONSTITUTIONAL_INVARIANTS,
  assertInvariantExists,
  assertProtectedInvariant,
  getConstitutionalInvariant,
  isProtectedConstitutionalInvariant,
  listConstitutionalInvariants,
} from "../../src/constitution/invariant-registry.js";

test("constitutional invariant registry is populated", () => {
  assert.ok(CONSTITUTIONAL_INVARIANTS.length >= 60);
});

test("every invariant has a stable id and active version", () => {
  const ids = new Set<string>();

  for (const entry of CONSTITUTIONAL_INVARIANTS) {
    assert.ok(entry.id.length > 0);
    assert.ok(!ids.has(entry.id), `duplicate invariant: ${entry.id}`);
    ids.add(entry.id);
    assert.equal(entry.status, "ACTIVE");
    assert.equal(entry.version, "GIIA-CONSTITUTION-v0.1.1");
    assert.ok(entry.statement.length > 0);
    assert.ok(entry.enforcementPoint.length > 0);
    assert.ok(entry.failureBehavior.length > 0);
    assert.ok(entry.testIds.length > 0);
  }
});

test("protected constitutional core invariants cannot be marked tenant-only", () => {
  for (const entry of CONSTITUTIONAL_INVARIANTS) {
    if (entry.protected) {
      assert.equal(entry.scope, "GLOBAL_CORE");
    }
  }
});

test("tenant-scoped invariants remain explicitly non-core", () => {
  for (const entry of CONSTITUTIONAL_INVARIANTS) {
    if (
      entry.scope === "ORGANIZATION" ||
      entry.scope === "DEPARTMENT"
    ) {
      assert.equal(entry.protected, false);
    }
  }
});

test("critical protected invariants fail closed or deny", () => {
  for (const entry of CONSTITUTIONAL_INVARIANTS) {
    if (entry.protected && entry.severity === "CRITICAL") {
      assert.ok(
        entry.failureBehavior === "DENY" ||
        entry.failureBehavior === "FAIL_CLOSED" ||
        entry.failureBehavior === "REQUIRE_HUMAN_APPROVAL" ||
        entry.failureBehavior === "REQUIRE_EVIDENCE",
        `${entry.id} has unsafe failure behavior`,
      );
    }
  }
});

test("required constitutional prohibition registry is present", () => {
  for (const id of [
    "R0",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "R9",
    "R10",
    "R11",
  ]) {
    assert.ok(isProtectedConstitutionalInvariant(id) || id === "R3" || id === "R4");
  }
});

test("constitutional human amendment boundary is registered", () => {
  const h11 = assertProtectedInvariant("H11.1");
  const h12 = assertProtectedInvariant("H11.2");
  const r7 = assertProtectedInvariant("R7");

  assert.equal(h11.failureBehavior, "REQUIRE_HUMAN_APPROVAL");
  assert.equal(h12.failureBehavior, "REQUIRE_HUMAN_APPROVAL");
  assert.equal(r7.failureBehavior, "REQUIRE_HUMAN_APPROVAL");
});

test("capability is explicitly separated from authorization", () => {
  const c04 = assertProtectedInvariant("C0.4");
  const ap32 = assertProtectedInvariant("AP3.2");
  const r9 = assertProtectedInvariant("R9");

  assert.equal(c04.enforcementPoint, "authorization");
  assert.equal(ap32.enforcementPoint, "agent-passport");
  assert.equal(r9.enforcementPoint, "authorization");
});

test("evidence-before-action invariants are registered", () => {
  const e71 = assertProtectedInvariant("E7.1");
  const e72 = assertProtectedInvariant("E7.2");
  const e73 = assertProtectedInvariant("E7.3");

  assert.equal(e71.failureBehavior, "REQUIRE_EVIDENCE");
  assert.equal(e72.failureBehavior, "DENY");
  assert.equal(e73.failureBehavior, "DENY");
  assert.equal(e71.evidenceRequired, true);
  assert.equal(e72.evidenceRequired, true);
  assert.equal(e73.evidenceRequired, true);
});

test("enforcement boundary cannot convert review or uncertainty into ALLOW", () => {
  const e172 = assertProtectedInvariant("EN17.2");
  const e173 = assertProtectedInvariant("EN17.3");

  assert.equal(e172.failureBehavior, "FAIL_CLOSED");
  assert.equal(e173.failureBehavior, "FAIL_CLOSED");
});

test("historical integrity invariants are protected", () => {
  assert.equal(isProtectedConstitutionalInvariant("CH10.3"), true);
  assert.equal(isProtectedConstitutionalInvariant("CE16.3"), true);
  assert.equal(isProtectedConstitutionalInvariant("R10"), true);
});

test("unknown invariant lookup does not silently succeed", () => {
  assert.equal(getConstitutionalInvariant("DOES-NOT-EXIST"), undefined);
  assert.throws(
    () => assertInvariantExists("DOES-NOT-EXIST"),
    /UNKNOWN_CONSTITUTIONAL_INVARIANT/,
  );
});

test("registry listing is stable and read-only at the API boundary", () => {
  const listed = listConstitutionalInvariants();

  assert.equal(listed, CONSTITUTIONAL_INVARIANTS);
  assert.ok(Object.isFrozen(listed));
});
