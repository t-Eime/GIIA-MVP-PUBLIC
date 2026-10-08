import assert from "node:assert/strict";
import { test } from "node:test";
import { unlinkSync } from "node:fs";

import { createMvpComposition } from "../../src/mvp/composition.js";

const NOW = "2026-10-04T10:00:00.000Z";
const LATER = "2026-10-04T10:00:01.000Z";

function remove(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    // Test cleanup is intentionally idempotent.
  }
}

test("MVP replay protection rejects the same request ID twice", () => {
  const composition = createMvpComposition();

  const input = {
    requestId: "mvp-replay-001",
    action: "read",
    resource: "resource-001",
    requestedAt: NOW,
  };

  const first = composition.evaluate(input);

  assert.ok(first);

  assert.throws(
    () => composition.evaluate({
      ...input,
      requestedAt: LATER,
    }),
    /REPLAY_REQUEST_REJECTED/,
  );

  composition.close();
});

test("MVP replay protection survives composition restart", () => {
  const path = ".test-mvp-replay.sqlite";
  remove(path);

  const input = {
    requestId: "mvp-restart-replay-001",
    action: "read",
    resource: "resource-001",
    requestedAt: NOW,
  };

  const first = createMvpComposition({
    trustRegistryPath: path,
    evidenceAuditRegistryPath: ".test-mvp-replay-evidence.sqlite",
  });

  const result = first.evaluate(input);

  assert.ok(result);

  first.close();

  const second = createMvpComposition({
    trustRegistryPath: path,
    evidenceAuditRegistryPath: ".test-mvp-replay-evidence-2.sqlite",
  });

  assert.throws(
    () => second.evaluate({
      ...input,
      requestedAt: LATER,
    }),
    /REPLAY_REQUEST_REJECTED/,
  );

  second.close();

  remove(path);
  remove(`${path}-wal`);
  remove(`${path}-shm`);
  remove(".test-mvp-replay-evidence.sqlite");
  remove(".test-mvp-replay-evidence.sqlite-wal");
  remove(".test-mvp-replay-evidence.sqlite-shm");
  remove(".test-mvp-replay-evidence-2.sqlite");
  remove(".test-mvp-replay-evidence-2.sqlite-wal");
  remove(".test-mvp-replay-evidence-2.sqlite-shm");
});
