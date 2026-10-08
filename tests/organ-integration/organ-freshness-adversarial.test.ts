import test from "node:test";
import assert from "node:assert/strict";

import {
  createGovernedFixture,
  evaluateFixture,
} from "../helpers/governed-pipeline-fixture.js";

import {
  assessPipelineWithOrgans,
} from "../../src/organ-integration/service.js";

test("organ assessment preserves the original pipeline timestamp", () => {
  const { request } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(
    result,
    result.request.requestedAt,
  );

  assert.equal(
    assessment.governor.issuedAt,
    result.request.requestedAt,
  );

  assert.equal(
    assessment.guardian.issuedAt,
    result.request.requestedAt,
  );
});

test("future-dated organ assessment is rejected", () => {
  const { request } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const future = new Date(
    Date.now() + 60_000,
  ).toISOString();

  assert.throws(() =>
    assessPipelineWithOrgans(result, future),
  );
});

test("organ assessment cannot be replayed with a different assessment timestamp", () => {
  const { request } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const original = assessPipelineWithOrgans(
    result,
    result.request.requestedAt,
  );

  const later = new Date(
    new Date(result.request.requestedAt).getTime() + 60_000,
  ).toISOString();

  assert.notEqual(
    original.governor.issuedAt,
    later,
  );

  assert.notEqual(
    original.guardian.issuedAt,
    later,
  );

  assert.equal(
    original.projection.requestId,
    result.request.id,
  );
});
