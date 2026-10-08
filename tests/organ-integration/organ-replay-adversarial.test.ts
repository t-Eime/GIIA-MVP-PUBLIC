import test from "node:test";
import assert from "node:assert/strict";

import { createGovernedFixture, evaluateFixture } from "../helpers/governed-pipeline-fixture.js";
import { assessPipelineWithOrgans } from "../../src/organ-integration/service.js";

test("organ assessment is bound to the original request timestamp", () => {
  const { request } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(
    result,
    result.request.requestedAt,
  );

  assert.equal(
    assessment.projection.requestId,
    result.request.id,
  );

  assert.equal(
    assessment.governor.requestId,
    result.request.id,
  );

  assert.equal(
    assessment.guardian.requestId,
    result.request.id,
  );
});

test("reusing an organ assessment cannot change the governed request", () => {
  const first = createGovernedFixture();
  const firstResult = evaluateFixture(first.request);

  assert.equal(firstResult.outcome, "SUCCESS");

  if (firstResult.outcome !== "SUCCESS") return;

  const firstAssessment = assessPipelineWithOrgans(
    firstResult,
    firstResult.request.requestedAt,
  );

  const substitutedRequest = {
    ...first.request,
    id: "request-002",
    authorizationRequest: {
      ...first.request.authorizationRequest,
      id: "request-002",
    },
  };

  assert.notEqual(
    firstAssessment.projection.requestId,
    substitutedRequest.id,
  );

  assert.equal(
    firstAssessment.projection.requestId,
    firstResult.request.id,
  );

  assert.equal(
    firstAssessment.governor.requestId,
    firstResult.request.id,
  );

  assert.equal(
    firstAssessment.guardian.requestId,
    firstResult.request.id,
  );
});

test("organ assessment cannot manufacture execution permission through replay", () => {
  const { request } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(
    result,
    result.request.requestedAt,
  );

  assert.equal(
    assessment.projection.executionPermitted,
    false,
  );
});

test("organ assessment remains bound to the original actor", () => {
  const { request } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(
    result,
    result.request.requestedAt,
  );

  assert.equal(
    assessment.projection.actorId,
    result.identity.id,
  );

  assert.equal(
    assessment.governor.actorId,
    result.identity.id,
  );

  assert.equal(
    assessment.guardian.actorId,
    result.identity.id,
  );
});

test("organ assessment remains bound to the original action and target", () => {
  const { request } = createGovernedFixture();
  const result = evaluateFixture(request);

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") return;

  const assessment = assessPipelineWithOrgans(
    result,
    result.request.requestedAt,
  );

  assert.equal(
    assessment.projection.action,
    result.request.action,
  );

  assert.equal(
    assessment.projection.target,
    result.request.resource,
  );

  assert.equal(
    assessment.governor.action,
    result.request.action,
  );

  assert.equal(
    assessment.guardian.action,
    result.request.action,
  );

  assert.equal(
    assessment.governor.target,
    result.request.resource,
  );

  assert.equal(
    assessment.guardian.target,
    result.request.resource,
  );
});
