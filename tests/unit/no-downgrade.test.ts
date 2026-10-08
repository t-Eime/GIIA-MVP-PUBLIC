import test from "node:test";
import assert from "node:assert/strict";

import {
  CONSTITUTIONAL_INVARIANTS,
  type ConstitutionalInvariant,
} from "../../src/constitution/invariant-registry.js";
import {
  assertNoConstitutionalDowngrade,
  compareConstitutionalVersions,
} from "../../src/constitution/no-downgrade.js";

function cloneRegistry(): ConstitutionalInvariant[] {
  return CONSTITUTIONAL_INVARIANTS.map((item) => ({ ...item }));
}

test("unchanged constitutional registry passes non-regression", () => {
  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    CONSTITUTIONAL_INVARIANTS,
  );

  assert.equal(result.allowed, true);
  assert.equal(result.violations.length, 0);
});

test("protected invariant removal is denied", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex((item) => item.protected);

  assert.notEqual(index, -1);
  proposed.splice(index, 1);

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "REMOVED_PROTECTED_INVARIANT",
    ),
  );
});

test("protected invariant cannot become unprotected", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex((item) => item.protected);

  assert.notEqual(index, -1);
  proposed[index] = { ...proposed[index]!, protected: false };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some((item) => item.code === "PROTECTION_REMOVED"),
  );
});

test("protected core cannot be moved to a weaker scope", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex(
    (item) => item.protected && item.scope === "GLOBAL_CORE",
  );

  assert.notEqual(index, -1);
  proposed[index] = { ...proposed[index]!, scope: "DOMAIN" };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some((item) => item.code === "SCOPE_WEAKENED"),
  );
});

test("protected fail-closed behavior cannot become permissive", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex(
    (item) =>
      item.protected &&
      (item.failureBehavior === "DENY" ||
        item.failureBehavior === "FAIL_CLOSED"),
  );

  assert.notEqual(index, -1);
  proposed[index] = {
    ...proposed[index]!,
    failureBehavior: "REQUIRE_REVIEW",
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "FAILURE_BEHAVIOR_WEAKENED",
    ),
  );
});

test("required evidence cannot be removed", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex(
    (item) => item.evidenceRequired === true,
  );

  assert.notEqual(index, -1);
  proposed[index] = { ...proposed[index]!, evidenceRequired: false };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "EVIDENCE_REQUIREMENT_REMOVED",
    ),
  );
});

test("stronger controls remain allowed", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex(
    (item) => item.scope === "GLOBAL_CORE" && item.failureBehavior === "DENY",
  );

  assert.notEqual(index, -1);

  proposed[index] = {
    ...proposed[index]!,
    evidenceRequired: true,
    failureBehavior: "DENY",
    scope: "GLOBAL_CORE",
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, true);
  assert.equal(result.violations.length, 0);
});

test("assertion fails closed on constitutional downgrade", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex((item) => item.protected);

  assert.notEqual(index, -1);
  proposed[index] = { ...proposed[index]!, protected: false };

  assert.throws(
    () =>
      assertNoConstitutionalDowngrade(
        CONSTITUTIONAL_INVARIANTS,
        proposed,
      ),
    /CONSTITUTIONAL_NON_REGRESSION_FAILED/,
  );
});

test("unknown new invariants do not weaken existing protected invariants", () => {
  const proposed = cloneRegistry();

  proposed.push({
    id: "TEST-NEW-STRONGER",
    family: "TEST",
    statement: "Additional constitutional protection.",
    severity: "CRITICAL",
    protected: true,
    scope: "GLOBAL_CORE",
    enforcementPoint: "TEST",
    failureBehavior: "DENY",
    evidenceRequired: true,
    testIds: ["no-downgrade-test"],
    version: "1.0.0",
    status: "ACTIVE",
  });

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, true);
});


test("duplicate invariant IDs are rejected", () => {
  const proposed = cloneRegistry();
  proposed.push({ ...proposed[0]! });

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "DUPLICATE_INVARIANT_ID",
    ),
  );
});

test("empty invariant IDs are rejected", () => {
  const proposed = cloneRegistry();
  proposed[0] = { ...proposed[0]!, id: "   " };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "INVALID_INVARIANT_ID",
    ),
  );
});

test("invalid invariant lifecycle status is rejected", () => {
  const proposed = cloneRegistry();

  proposed[0] = {
    ...proposed[0]!,
    status: "REVOKED",
  } as unknown as ConstitutionalInvariant;

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "STATUS_INVALID",
    ),
  );
});


test("protected invariant severity cannot be weakened", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex((item) => item.severity === "CRITICAL");

  assert.notEqual(index, -1);

  proposed[index] = {
    ...proposed[index]!,
    severity: "NORMAL",
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "SEVERITY_WEAKENED",
    ),
  );
});

test("constitutional invariant statement changes require review", () => {
  const proposed = cloneRegistry();

  proposed[0] = {
    ...proposed[0]!,
    statement: `${proposed[0]!.statement} Additional wording.`,
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "STATEMENT_CHANGED",
    ),
  );
});

test("constitutional invariant family changes require review", () => {
  const proposed = cloneRegistry();

  proposed[0] = {
    ...proposed[0]!,
    family: `${proposed[0]!.family}-ALTERED`,
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "FAMILY_CHANGED",
    ),
  );
});

test("constitutional enforcement-point changes require review", () => {
  const proposed = cloneRegistry();

  proposed[0] = {
    ...proposed[0]!,
    enforcementPoint: `${proposed[0]!.enforcementPoint}:altered`,
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "ENFORCEMENT_POINT_CHANGED",
    ),
  );
});

test("constitutional test coverage cannot be removed", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex((item) => item.testIds.length > 0);

  assert.notEqual(index, -1);

  proposed[index] = {
    ...proposed[index]!,
    testIds: proposed[index]!.testIds.slice(1),
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, false);
  assert.ok(
    result.violations.some(
      (item) => item.code === "TEST_COVERAGE_REMOVED",
    ),
  );
});

test("stronger severity remains allowed", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex((item) => item.severity === "HIGH");

  assert.notEqual(index, -1);

  proposed[index] = {
    ...proposed[index]!,
    severity: "CRITICAL",
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, true);
  assert.equal(
    result.violations.some(
      (item) => item.code === "SEVERITY_WEAKENED",
    ),
    false,
  );
});

test("additional constitutional test coverage remains allowed", () => {
  const proposed = cloneRegistry();
  const index = proposed.findIndex((item) => item.testIds.length > 0);

  assert.notEqual(index, -1);

  proposed[index] = {
    ...proposed[index]!,
    testIds: [...proposed[index]!.testIds, "ADDITIONAL-TEST"],
  };

  const result = compareConstitutionalVersions(
    CONSTITUTIONAL_INVARIANTS,
    proposed,
  );

  assert.equal(result.allowed, true);
  assert.equal(
    result.violations.some(
      (item) => item.code === "TEST_COVERAGE_REMOVED",
    ),
    false,
  );
});
