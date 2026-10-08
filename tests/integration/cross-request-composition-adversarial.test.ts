import test from "node:test";
import assert from "node:assert/strict";

import {
  createGovernedFixture,
  evaluateFixture,
} from "../helpers/governed-pipeline-fixture.js";

/*
 * CORE-001-AUTH adversarial composition suite.
 *
 * NEGATIVE SECURITY PROPERTY:
 *
 * A valid artifact from request A must not become valid for request B merely
 * because the remaining artifacts are individually valid.
 *
 * The test deliberately invokes the real authoritative pipeline.
 * It does not construct a second authorization implementation.
 */

function evaluate(request: ReturnType<typeof createGovernedFixture>["request"]) {
  return evaluateFixture(request);
}

function assertDeniedOrNonAuthoritative(
  result: ReturnType<typeof evaluate>,
  label: string,
) {
  /*
   * A composition attack succeeds only if it obtains an authoritative ALLOW.
   * Any failure, DENY, DEFER, CONTAIN, or non-authoritative result is safe.
   */
  const authoritativeAllow =
    result.outcome === "SUCCESS" &&
    result.decision.authoritative === true &&
    result.decision.decision === "ALLOW";

  assert.equal(
    authoritativeAllow,
    false,
    label,
  );
}

test("CORE-001-AUTH-001 baseline independently governed request is authoritative", () => {
  const fixture = createGovernedFixture();

  const result = evaluate(fixture.request);

  assert.equal(result.outcome, "SUCCESS");
  assert.equal(result.decision.authoritative, true);
  assert.equal(result.decision.decision, "ALLOW");

  fixture.registry.close();
});

test("CORE-001-AUTH-002 substituted authorization request cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  /*
   * Preserve A's identity/trust/evidence/audit while replacing the
   * authorization object with B's independently produced authorization.
   */
  const attack = {
    ...a.request,
    authorizationRequest: b.request.authorizationRequest,
  };

  const result = evaluate(attack);

  assertDeniedOrNonAuthoritative(
    result,
    "authorization from another governed request must not authorize A",
  );

  a.registry.close();
  b.registry.close();
});

test("CORE-001-AUTH-003 substituted identity cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  const attack = {
    ...a.request,
    identity: b.request.identity,
  };

  const result = evaluate(attack);

  assertDeniedOrNonAuthoritative(
    result,
    "identity substitution must not produce authoritative ALLOW",
  );

  a.registry.close();
  b.registry.close();
});

test("CORE-001-AUTH-004 substituted authority cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  const attack = {
    ...a.request,
    authority: b.request.authority,
  };

  const result = evaluate(attack);

  assertDeniedOrNonAuthoritative(
    result,
    "authority substitution must not produce authoritative ALLOW",
  );

  a.registry.close();
  b.registry.close();
});

test("CORE-001-AUTH-005 substituted trust chain cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  const attack = {
    ...a.request,
    trustChain: b.request.trustChain,
  };

  const result = evaluate(attack);

  assertDeniedOrNonAuthoritative(
    result,
    "trust-chain substitution must not produce authoritative ALLOW",
  );

  a.registry.close();
  b.registry.close();
});

test("CORE-001-AUTH-006 substituted evidence cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  const attack = {
    ...a.request,
    evidence: b.request.evidence,
  };

  const result = evaluate(attack);

  assertDeniedOrNonAuthoritative(
    result,
    "evidence from another request must not produce authoritative ALLOW",
  );

  a.registry.close();
  b.registry.close();
});

test("CORE-001-AUTH-007 substituted audit cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  const attack = {
    ...a.request,
    audit: b.request.audit,
  };

  const result = evaluate(attack);

  assertDeniedOrNonAuthoritative(
    result,
    "audit from another request must not produce authoritative ALLOW",
  );

  a.registry.close();
  b.registry.close();
});

test("CORE-001-AUTH-008 mixed authorization plus evidence cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  const attack = {
    ...a.request,
    authorizationRequest: b.request.authorizationRequest,
    evidence: b.request.evidence,
    audit: b.request.audit,
  };

  const result = evaluate(attack);

  assertDeniedOrNonAuthoritative(
    result,
    "mixed artifacts from another request must not become authoritative ALLOW",
  );

  a.registry.close();
  b.registry.close();
});

test("CORE-001-AUTH-009 mixed trust plus authorization cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  const attack = {
    ...a.request,
    trustChain: b.request.trustChain,
    authorizationRequest: b.request.authorizationRequest,
  };

  const result = evaluate(attack);

  assertDeniedOrNonAuthoritative(
    result,
    "mixed trust and authorization artifacts must remain bound",
  );

  a.registry.close();
  b.registry.close();
});

test("CORE-001-AUTH-010 full cross-request artifact assembly cannot obtain authoritative ALLOW", () => {
  const a = createGovernedFixture("A");
  const b = createGovernedFixture("B");

  const attack = {
    ...a.request,
    identity: b.request.identity,
    authority: b.request.authority,
    trustChain: b.request.trustChain,
    authorizationRequest: b.request.authorizationRequest,
    evidence: b.request.evidence,
    audit: b.request.audit,
  };

  const result = evaluate(attack);

  /*
   * This is the important negative property:
   * assembling valid artifacts must not manufacture authority.
   */
  assertDeniedOrNonAuthoritative(
    result,
    "cross-request assembly must not manufacture authoritative ALLOW",
  );

  a.registry.close();
  b.registry.close();
});
