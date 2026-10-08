import test from "node:test";
import assert from "node:assert/strict";
import { ResilienceService } from "../../src/resilience/service.js";

test("legacy authority-only resilience transition is fail-closed", () => {
  const service = new ResilienceService(
    {} as never,
  );

  assert.throws(
    () => service.transition(),
    /RESILIENCE_AUTHORIZATION_REQUIRED/,
  );
});
