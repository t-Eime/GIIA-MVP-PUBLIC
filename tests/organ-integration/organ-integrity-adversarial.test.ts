import test from "node:test";
import assert from "node:assert/strict";

import { createGovernedFixture, evaluateFixture } from "../helpers/governed-pipeline-fixture.js";
import { assessPipelineWithOrgans } from "../../src/organ-integration/service.js";

test("organ assessment preserves exact request identity", () => {
  const { request, registry } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(result, result.request.requestedAt);

  assert.equal(assessment.projection.requestId, result.request.id);
  assert.equal(assessment.projection.actorId, result.identity.id);
  assert.equal(assessment.projection.action, result.request.action);
  assert.equal(assessment.projection.target, result.request.resource);
});

test("organ results cannot be rebound to another request", () => {
  const { request, registry } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(result, result.request.requestedAt);

  const forgedRequestId = `${assessment.projection.requestId}-forged`;

  assert.notEqual(
    assessment.governor.requestId,
    forgedRequestId,
  );

  assert.notEqual(
    assessment.guardian.requestId,
    forgedRequestId,
  );

  assert.equal(
    assessment.governor.requestId,
    assessment.projection.requestId,
  );

  assert.equal(
    assessment.guardian.requestId,
    assessment.projection.requestId,
  );
});

test("Governor and Guardian cannot silently disagree on the authoritative pipeline decision", () => {
  const { request, registry } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(result, result.request.requestedAt);

  assert.equal(
    assessment.projection.pipelineDecision,
    "ALLOW",
  );

  assert.equal(
    assessment.governor.decision,
    "ALLOW",
  );

  assert.equal(
    assessment.guardian.decision,
    "ALLOW",
  );
});

test("organ assessment never changes execution permission", () => {
  const { request, registry } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(result, result.request.requestedAt);

  assert.equal(
    assessment.projection.executionPermitted,
    false,
  );
});

test("organ results preserve pipeline provenance", () => {
  const { request, registry } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(result, result.request.requestedAt);

  assert.equal(
    assessment.projection.pipelineProvenance,
    result.decision.provenance,
  );
});

test("organ assessment may occur after the original request timestamp", () => {
  const { request, registry } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const future = new Date(
    new Date(result.request.requestedAt).getTime() + 60_000,
  ).toISOString();

  const assessment = assessPipelineWithOrgans(result, future);

  assert.equal(
    assessment.projection.requestId,
    result.request.id,
  );

  assert.equal(
    assessment.projection.executionPermitted,
    false,
  );
});
