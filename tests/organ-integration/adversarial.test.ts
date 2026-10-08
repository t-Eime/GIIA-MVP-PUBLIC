import test from "node:test";
import assert from "node:assert/strict";

import {
  assessPipelineWithOrgans,
  projectPipelineForOrgans,
} from "../../src/organ-integration/service.js";

import {
  createGovernedFixture,
  evaluateFixture,
  NOW,
} from "../helpers/governed-pipeline-fixture.js";

test("real pipeline ALLOW produces Governor and Guardian ALLOW", () => {
  const f = createGovernedFixture();
  const pipeline = evaluateFixture(f.request);

  assert.equal(pipeline.outcome, "SUCCESS");

  if (pipeline.outcome !== "SUCCESS") {
    throw new Error("Expected real governed pipeline to succeed");
  }

  const assessment = assessPipelineWithOrgans(
    pipeline,
    NOW,
  );

  assert.equal(pipeline.decision.decision, "ALLOW");
  assert.equal(assessment.governor.decision, "ALLOW");
  assert.equal(assessment.guardian.decision, "ALLOW");

  f.registry.close();
});

test("real pipeline DENY cannot become Governor ALLOW", () => {
  const f = createGovernedFixture();

  const request = {
    ...f.request,
    authority: {
      ...f.request.authority,
      status: "revoked" as const,
    },
  };

  const pipeline = evaluateFixture(request);

  assert.equal(pipeline.outcome, "FAILURE");
  assert.notEqual(pipeline.decision.decision, "ALLOW");

  f.registry.close();
});

test("real pipeline trust failure cannot become Guardian ALLOW", () => {
  const f = createGovernedFixture();

  const request = {
    ...f.request,
    trustChain: {
      ...f.request.trustChain,
      credential: {
        ...f.request.trustChain.credential,
        signature: "FORGED",
      },
    },
  };

  const pipeline = evaluateFixture(request);

  assert.equal(pipeline.outcome, "FAILURE");
  assert.notEqual(pipeline.decision.decision, "ALLOW");

  f.registry.close();
});

test("real pipeline jurisdiction failure cannot become an organ ALLOW", () => {
  const f = createGovernedFixture();

  const baseRule = f.request.governanceRules[0];

  if (!baseRule) {
    throw new Error("Expected governance rule in fixture");
  }

  const request = {
    ...f.request,
    jurisdiction: "JURISDICTION-B",
    governanceRules: [
      {
        ...baseRule,
        jurisdiction: "JURISDICTION-A",
      },
    ],
  };

  const pipeline = evaluateFixture(request);

  assert.equal(pipeline.outcome, "FAILURE");
  assert.notEqual(pipeline.decision.decision, "ALLOW");

  f.registry.close();
});

test("pipeline ALLOW does not create execution authority", () => {
  const f = createGovernedFixture();
  const pipeline = evaluateFixture(f.request);

  assert.equal(pipeline.outcome, "SUCCESS");

  if (pipeline.outcome !== "SUCCESS") {
    throw new Error("Expected successful pipeline");
  }

  const projection = projectPipelineForOrgans(pipeline);

  assert.equal(projection.pipelineDecision, "ALLOW");
  assert.equal(projection.executionPermitted, false);

  f.registry.close();
});

test("projection preserves exact request binding", () => {
  const f = createGovernedFixture();
  const pipeline = evaluateFixture(f.request);

  assert.equal(pipeline.outcome, "SUCCESS");

  if (pipeline.outcome !== "SUCCESS") {
    throw new Error("Expected successful pipeline");
  }

  const projection = projectPipelineForOrgans(pipeline);

  assert.equal(
    projection.requestId,
    pipeline.request.id,
  );

  assert.equal(
    projection.actorId,
    pipeline.request.subjectIdentityId,
  );

  assert.equal(
    projection.action,
    pipeline.request.action,
  );

  assert.equal(
    projection.target,
    pipeline.request.resource,
  );

  f.registry.close();
});

test("projection preserves authoritative pipeline provenance", () => {
  const f = createGovernedFixture();
  const pipeline = evaluateFixture(f.request);

  assert.equal(pipeline.outcome, "SUCCESS");

  if (pipeline.outcome !== "SUCCESS") {
    throw new Error("Expected successful pipeline");
  }

  const projection = projectPipelineForOrgans(pipeline);

  assert.equal(
    projection.pipelineProvenance,
    pipeline.decision.provenance,
  );

  f.registry.close();
});

test("successful organ assessment cannot remove enforcement boundary", () => {
  const f = createGovernedFixture();
  const pipeline = evaluateFixture(f.request);

  assert.equal(pipeline.outcome, "SUCCESS");

  if (pipeline.outcome !== "SUCCESS") {
    throw new Error("Expected successful pipeline");
  }

  const assessment = assessPipelineWithOrgans(
    pipeline,
    NOW,
  );

  assert.equal(assessment.governor.decision, "ALLOW");
  assert.equal(assessment.guardian.decision, "ALLOW");
  assert.equal(assessment.projection.executionPermitted, false);

  f.registry.close();
});
