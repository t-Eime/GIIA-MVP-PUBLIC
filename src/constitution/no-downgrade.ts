import {
  CONSTITUTIONAL_INVARIANTS,
  type ConstitutionalInvariant,
} from "./invariant-registry.js";

export type NoDowngradeViolationCode =
  | "REMOVED_PROTECTED_INVARIANT"
  | "PROTECTION_REMOVED"
  | "SCOPE_WEAKENED"
  | "FAILURE_BEHAVIOR_WEAKENED"
  | "EVIDENCE_REQUIREMENT_REMOVED"
  | "VERSION_INVALID"
  | "INVALID_INVARIANT_ID"
  | "DUPLICATE_INVARIANT_ID"
  | "STATUS_INVALID"
  | "SEVERITY_WEAKENED"
  | "STATEMENT_CHANGED"
  | "FAMILY_CHANGED"
  | "ENFORCEMENT_POINT_CHANGED"
  | "TEST_COVERAGE_REMOVED"
  | "UNKNOWN_BASELINE_INVARIANT"
  | "AMBIGUOUS_COMPARISON";

export interface NoDowngradeViolation {
  readonly code: NoDowngradeViolationCode;
  readonly invariantId: string;
  readonly message: string;
}

export interface NoDowngradeResult {
  readonly allowed: boolean;
  readonly violations: readonly NoDowngradeViolation[];
}

const FAILURE_STRENGTH: Readonly<Record<string, number>> = Object.freeze({
  DENY: 5,
  FAIL_CLOSED: 5,
  REQUIRE_HUMAN_APPROVAL: 4,
  REQUIRE_EVIDENCE: 4,
  REQUIRE_REVIEW: 3,
});

const SCOPE_STRENGTH: Readonly<Record<string, number>> = Object.freeze({
  GLOBAL_CORE: 5,
  ORGANIZATION: 4,
  DEPARTMENT: 3,
  DOMAIN: 2,
  OPERATIONAL: 1,
});

function violation(
  code: NoDowngradeViolationCode,
  invariantId: string,
  message: string,
): NoDowngradeViolation {
  return Object.freeze({ code, invariantId, message });
}

function compareInvariant(
  before: ConstitutionalInvariant,
  after: ConstitutionalInvariant,
): NoDowngradeViolation[] {
  const violations: NoDowngradeViolation[] = [];

  if (before.id.trim() === "" || after.id.trim() === "") {
    violations.push(
      violation(
        "INVALID_INVARIANT_ID",
        before.id || after.id,
        "Constitutional invariant IDs must be non-empty.",
      ),
    );
  }

  if (before.version.trim() === "" || after.version.trim() === "") {
    violations.push(
      violation(
        "VERSION_INVALID",
        before.id,
        "Constitutional invariant versions must be non-empty.",
      ),
    );
  }

  const severityStrength: Readonly<Record<string, number>> = Object.freeze({
    CRITICAL: 3,
    HIGH: 2,
    NORMAL: 1,
  });

  const beforeSeverity = severityStrength[before.severity];
  const afterSeverity = severityStrength[after.severity];

  if (
    beforeSeverity === undefined ||
    afterSeverity === undefined ||
    afterSeverity < beforeSeverity
  ) {
    violations.push(
      violation(
        "SEVERITY_WEAKENED",
        before.id,
        `Invariant severity weakened from ${before.severity} to ${after.severity}.`,
      ),
    );
  }

  if (before.statement !== after.statement) {
    violations.push(
      violation(
        "STATEMENT_CHANGED",
        before.id,
        "Constitutional invariant statement changed and requires explicit constitutional review.",
      ),
    );
  }

  if (before.family !== after.family) {
    violations.push(
      violation(
        "FAMILY_CHANGED",
        before.id,
        "Constitutional invariant family changed and requires explicit constitutional review.",
      ),
    );
  }

  if (before.enforcementPoint !== after.enforcementPoint) {
    violations.push(
      violation(
        "ENFORCEMENT_POINT_CHANGED",
        before.id,
        "Constitutional invariant enforcement point changed and requires explicit constitutional review.",
      ),
    );
  }

  const beforeTests = new Set(before.testIds);
  const afterTests = new Set(after.testIds);

  for (const testId of beforeTests) {
    if (!afterTests.has(testId)) {
      violations.push(
        violation(
          "TEST_COVERAGE_REMOVED",
          before.id,
          `Constitutional verification coverage removed: ${testId}.`,
        ),
      );
    }
  }

  if (before.protected && !after.protected) {
    violations.push(
      violation(
        "PROTECTION_REMOVED",
        before.id,
        "A protected constitutional invariant cannot become unprotected.",
      ),
    );
  }

  const beforeScope = SCOPE_STRENGTH[before.scope];
  const afterScope = SCOPE_STRENGTH[after.scope];

  if (
    before.protected &&
    (beforeScope === undefined || afterScope === undefined || afterScope < beforeScope)
  ) {
    violations.push(
      violation(
        "SCOPE_WEAKENED",
        before.id,
        "A protected invariant cannot be moved to a weaker governance scope.",
      ),
    );
  }

  const beforeFailure = FAILURE_STRENGTH[before.failureBehavior];
  const afterFailure = FAILURE_STRENGTH[after.failureBehavior];

  if (
    beforeFailure === undefined ||
    afterFailure === undefined ||
    (before.protected && afterFailure < beforeFailure)
  ) {
    violations.push(
      violation(
        "FAILURE_BEHAVIOR_WEAKENED",
        before.id,
        "A protected invariant cannot receive a weaker failure behavior.",
      ),
    );
  }

  if (before.evidenceRequired && !after.evidenceRequired) {
    violations.push(
      violation(
        "EVIDENCE_REQUIREMENT_REMOVED",
        before.id,
        "A required evidence condition cannot be removed.",
      ),
    );
  }

  return violations;
}

export function compareConstitutionalVersions(
  before: readonly ConstitutionalInvariant[],
  after: readonly ConstitutionalInvariant[],
): NoDowngradeResult {
  const violations: NoDowngradeViolation[] = [];

  const validateRegistryStructure = (
    registry: readonly ConstitutionalInvariant[],
    label: string,
  ): void => {
    const seen = new Set<string>();

    for (const item of registry) {
      if (item.id.trim() === "") {
        violations.push(
          violation(
            "INVALID_INVARIANT_ID",
            item.id,
            `${label} contains an invariant with an empty ID.`,
          ),
        );
      }

      if (seen.has(item.id)) {
        violations.push(
          violation(
            "DUPLICATE_INVARIANT_ID",
            item.id,
            `${label} contains duplicate invariant ID: ${item.id}.`,
          ),
        );
      }

      seen.add(item.id);

      if (item.status !== "ACTIVE") {
        violations.push(
          violation(
            "STATUS_INVALID",
            item.id,
            `${label} contains an invariant with an invalid lifecycle status.`,
          ),
        );
      }

      if (item.version.trim() === "") {
        violations.push(
          violation(
            "VERSION_INVALID",
            item.id,
            `${label} contains an invariant with an empty version.`,
          ),
        );
      }
    }
  };

  validateRegistryStructure(before, "Baseline");
  validateRegistryStructure(after, "Proposed");

  const afterById = new Map(after.map((item) => [item.id, item]));

  for (const previous of before) {
    const current = afterById.get(previous.id);

    if (!current) {
      if (previous.protected) {
        violations.push(
          violation(
            "REMOVED_PROTECTED_INVARIANT",
            previous.id,
            "A protected constitutional invariant cannot be removed.",
          ),
        );
      }
      continue;
    }

    violations.push(...compareInvariant(previous, current));
  }

  const result = Object.freeze({
    allowed: violations.length === 0,
    violations: Object.freeze(violations),
  });

  return result;
}

export function assertNoConstitutionalDowngrade(
  before: readonly ConstitutionalInvariant[],
  after: readonly ConstitutionalInvariant[],
): void {
  const result = compareConstitutionalVersions(before, after);

  if (!result.allowed) {
    throw new Error(
      `CONSTITUTIONAL_NON_REGRESSION_FAILED: ${result.violations
        .map((item) => `${item.code}:${item.invariantId}`)
        .join(",")}`,
    );
  }
}

export function compareAgainstCurrentConstitution(
  proposed: readonly ConstitutionalInvariant[],
): NoDowngradeResult {
  return compareConstitutionalVersions(CONSTITUTIONAL_INVARIANTS, proposed);
}
