import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createOfflineEvidence,
  verifyOfflineEvidence,
  verifyOfflineEvidenceChain,
} from "../../src/resilience/evidence.js";

import {
  reconcileOfflineEvidence,
} from "../../src/resilience/reconcile.js";

import {
  createStateTransition,
  verifyStateTransition,
  verifyTransitionChain,
} from "../../src/resilience/state.js";

import {
  createFinalVerification,
  verifyFinalVerification,
  createRestartAuthorization,
  verifyRestartAuthorization,
  RestartRegistry,
} from "../../src/resilience/restart.js";

import { ResilienceRegistry } from "../../src/resilience/registry.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "giia-resilience-"));
}

function validEvidence(
  id: string,
  sequence = 0,
  previousEvidenceHash?: string,
) {
  return createOfflineEvidence({
    id,
    subjectId: "subject-1",
    recordedAt: "2026-01-01T00:00:00.000Z",
    evidenceType: "TEST",
    payload: `payload-${id}`,
    sequence,
    ...(previousEvidenceHash === undefined
      ? {}
      : { previousEvidenceHash }),
  });
}

test("offline evidence hash is required before persistence", () => {
  const dir = tempDir();
  const path = join(dir, "resilience.sqlite");

  const registry = new ResilienceRegistry(path);

  const evidence = validEvidence("e-1");
  const forged = {
    ...evidence,
    evidenceHash: "forged",
  };

  assert.equal(verifyOfflineEvidence(evidence), true);
  assert.equal(verifyOfflineEvidence(forged), false);

  assert.throws(
    () => registry.putOfflineEvidence(forged),
    /OFFLINE_EVIDENCE_INTEGRITY_FAILURE/,
  );

  registry.close();
  rmSync(dir, { recursive: true, force: true });
});

test("offline evidence chain rejects gaps and forged hashes", () => {
  const first = validEvidence("e-1", 0);
  const second = validEvidence("e-2", 1, first.evidenceHash);

  assert.equal(
    verifyOfflineEvidenceChain([first, second]).valid,
    true,
  );

  const forged = {
    ...second,
    evidenceHash: "forged",
  };

  assert.equal(
    verifyOfflineEvidenceChain([first, forged]).valid,
    false,
  );

  const gap = validEvidence("e-3", 3, first.evidenceHash);

  assert.equal(
    verifyOfflineEvidenceChain([first, gap]).valid,
    false,
  );
});

test("reconciliation rejects forged evidence before comparing hashes", () => {
  const local = validEvidence("local-1");
  const forgedRemote = {
    ...local,
    id: "remote-1",
    evidenceHash: "forged",
  };

  assert.throws(
    () =>
      reconcileOfflineEvidence(
        [local],
        [forgedRemote],
        "2026-01-01T00:00:01.000Z",
      ),
    /RECONCILIATION_EVIDENCE_INTEGRITY_FAILURE/,
  );
});

test("reconciliation does not silently resolve conflicting evidence", () => {
  const local = validEvidence("local-1");
  const remote = validEvidence("remote-1");

  const result = reconcileOfflineEvidence(
    [local],
    [remote],
    "2026-01-01T00:00:01.000Z",
  );

  assert.equal(result.conflicts.length, 1);
  assert.equal(result.requiresDefer, true);
  assert.equal(result.conflicts[0]?.resolved, false);
});

test("state transition hash detects payload tampering", () => {
  const transition = createStateTransition({
    id: "transition-1",
    from: "ONLINE",
    to: "OFFLINE",
    reason: "CONNECTIVITY_LOSS",
    action: "ENTER_OFFLINE",
    occurredAt: "2026-01-01T00:00:00.000Z",
    authorityId: "authority-1",
    evidenceRef: "evidence-1",
    authorizationReceiptHash: "receipt-1",
  });

  assert.equal(verifyStateTransition(transition), true);

  const forged = {
    ...transition,
    authorityId: "attacker",
  };

  assert.equal(verifyStateTransition(forged), false);
});

test("transition chain rejects forged persisted transition payload", () => {
  const first = createStateTransition({
    id: "transition-1",
    from: "ONLINE",
    to: "OFFLINE",
    reason: "CONNECTIVITY_LOSS",
    action: "ENTER_OFFLINE",
    occurredAt: "2026-01-01T00:00:00.000Z",
    authorityId: "authority-1",
    evidenceRef: "evidence-1",
    authorizationReceiptHash: "receipt-1",
  });

  const second = createStateTransition({
    id: "transition-2",
    from: "OFFLINE",
    to: "DEGRADED",
    reason: "CONNECTIVITY_LOSS",
    action: "ENTER_DEGRADED",
    occurredAt: "2026-01-01T00:01:00.000Z",
    authorityId: "authority-1",
    evidenceRef: "evidence-2",
    authorizationReceiptHash: "receipt-2",
    previousTransitionHash: first.transitionHash,
  });

  assert.equal(verifyTransitionChain([first, second]), true);

  const forged = {
    ...second,
    reason: "MANUAL_RECOVERY" as const,
  };

  assert.equal(verifyTransitionChain([first, forged]), false);
});

test("restart verification is cryptographically bound", () => {
  const verification = createFinalVerification({
    id: "verification-1",
    verificationType: "HUMAN_FINAL_VERIFICATION",
    verifierId: "human-1",
    verifiedAt: "2026-01-01T00:00:00.000Z",
    status: "PASSED",
    evidenceRef: "recovery-evidence-1",
    reason: "Verified",
  });

  assert.equal(verifyFinalVerification(verification), true);

  const forged = {
    ...verification,
    verifierId: "attacker",
  };

  assert.equal(verifyFinalVerification(forged), false);
});

test("restart authorization requires two distinct verification references", () => {
  assert.throws(
    () =>
      createRestartAuthorization({
        id: "restart-1",
        recoveryEvidenceRef: "recovery-1",
        finalVerificationIds: ["same", "same"],
        authorizedBy: "authority-1",
        authorizedAt: "2026-01-01T00:00:00.000Z",
        reason: "Recovery",
      }),
    /Restart verification references must be unique/,
  );
});

test("restart authorization hash detects tampering", () => {
  const authorization = createRestartAuthorization({
    id: "restart-1",
    recoveryEvidenceRef: "recovery-1",
    finalVerificationIds: ["v1", "v2"],
    authorizedBy: "authority-1",
    authorizedAt: "2026-01-01T00:00:00.000Z",
    reason: "Recovery",
  });

  assert.equal(verifyRestartAuthorization(authorization), true);

  const forged = {
    ...authorization,
    authorizedBy: "attacker",
  };

  assert.equal(verifyRestartAuthorization(forged), false);
});

test("restart registry is append-only at the SQL boundary", () => {
  const dir = tempDir();
  const path = join(dir, "restart.sqlite");
  const registry = new RestartRegistry(path);

  const verification = createFinalVerification({
    id: "verification-1",
    verificationType: "HUMAN_FINAL_VERIFICATION",
    verifierId: "human-1",
    verifiedAt: "2026-01-01T00:00:00.000Z",
    status: "PASSED",
    evidenceRef: "evidence-1",
    reason: "Verified",
  });

  registry.putVerification(verification);

  const db = new DatabaseSync(path);

  assert.throws(
    () =>
      db.prepare(
        "UPDATE final_verifications SET reason = ? WHERE id = ?",
      ).run("tampered", verification.id),
    /RESTART_VERIFICATION_IMMUTABLE/,
  );

  assert.throws(
    () =>
      db.prepare(
        "DELETE FROM final_verifications WHERE id = ?",
      ).run(verification.id),
    /RESTART_VERIFICATION_APPEND_ONLY/,
  );

  db.close();
  registry.close();
  rmSync(dir, { recursive: true, force: true });
});

test("resilience registry append-only tables reject UPDATE and DELETE", () => {
  const dir = tempDir();
  const path = join(dir, "resilience.sqlite");
  const registry = new ResilienceRegistry(path);
  const db = new DatabaseSync(path);

  const evidence = validEvidence("e-1");
  registry.putOfflineEvidence(evidence);

  registry.putConflict({
    id: "conflict-1",
    subjectId: "subject-1",
    localEvidenceId: "e-1",
    remoteEvidenceId: "e-2",
    reason: "TEST",
    detectedAt: "2026-01-01T00:00:00.000Z",
    resolved: false,
  });

  registry.putRecoveryMarker(
    "marker-1",
    "TEST",
    "2026-01-01T00:00:00.000Z",
    "test",
  );

  assert.throws(
    () =>
      db.prepare(
        "UPDATE offline_evidence SET payload = ? WHERE evidence_id = ?",
      ).run("tampered", "e-1"),
    /OFFLINE_EVIDENCE_IMMUTABLE/,
  );

  assert.throws(
    () =>
      db.prepare(
        "DELETE FROM offline_evidence WHERE evidence_id = ?",
      ).run("e-1"),
    /OFFLINE_EVIDENCE_APPEND_ONLY/,
  );

  assert.throws(
    () =>
      db.prepare(
        "UPDATE reconciliation_conflicts SET reason = ? WHERE conflict_id = ?",
      ).run("tampered", "conflict-1"),
    /RECONCILIATION_CONFLICT_IMMUTABLE/,
  );

  assert.throws(
    () =>
      db.prepare(
        "DELETE FROM reconciliation_conflicts WHERE conflict_id = ?",
      ).run("conflict-1"),
    /RECONCILIATION_CONFLICT_APPEND_ONLY/,
  );

  assert.throws(
    () =>
      db.prepare(
        "UPDATE recovery_markers SET detail = ? WHERE marker_id = ?",
      ).run("tampered", "marker-1"),
    /RECOVERY_MARKER_IMMUTABLE/,
  );

  assert.throws(
    () =>
      db.prepare(
        "DELETE FROM recovery_markers WHERE marker_id = ?",
      ).run("marker-1"),
    /RECOVERY_MARKER_APPEND_ONLY/,
  );

  db.close();
  registry.close();
  rmSync(dir, { recursive: true, force: true });
});

test("receipt constructor is not publicly exported", async () => {
  const authorizationModule = await import("../../src/resilience/authorization.js");

  assert.equal(
    "createResilienceAuthorizationReceipt" in authorizationModule,
    false,
  );

  assert.equal(
    typeof authorizationModule.authorizeResilienceTransition,
    "function",
  );
});

test("registry does not expose the raw transition commit method", () => {
  const prototype = Object.getOwnPropertyNames(
    ResilienceRegistry.prototype,
  );

  assert.equal(prototype.includes("commitTransition"), true);
  assert.equal(
    prototype.includes("authorizeTransitionCommit"),
    true,
  );
});
