import test from "node:test";
import assert from "node:assert/strict";

import {
  createEvidenceHash,
  evidenceHash,
} from "../../src/evidence/service.js";
import { verifyEvidenceChain } from "../../src/evidence/chain.js";
import {
  auditHash,
  createAuditHash,
} from "../../src/audit/service.js";
import { verifyAuditChain } from "../../src/audit/chain.js";
import type { Evidence } from "../../src/evidence/types.js";
import type { AuditEvent } from "../../src/audit/types.js";

function makeEvidence(
  id: string,
  previousEvidenceHash?: string,
): Evidence {
  const evidence: Omit<Evidence, "recordHash"> = {
    id,
    kind: "event",
    subject: "identity-001",
    authorizationRequestId: "request-001",
    action: "read",
    occurredAt: "2026-01-02T00:00:00.000Z",
    recordedAt: "2026-01-02T00:00:01.000Z",
    source: "test",
    contentHash: `content-${id}`,
    provenance: "test",
  };

  if (previousEvidenceHash !== undefined) {
    evidence.previousEvidenceHash = previousEvidenceHash;
  }

  return {
    ...evidence,
    recordHash: createEvidenceHash(evidence),
  };
}

function makeAudit(
  id: string,
  previousAuditHash?: string,
): AuditEvent {
  const event: Omit<AuditEvent, "recordHash"> = {
    id,
    actor: "identity-001",
    authorizationRequestId: "request-001",
    evidenceId: "evidence-001",
    action: "read",
    resource: "resource-001",
    outcome: "EXECUTED",
    occurredAt: "2026-01-02T00:00:00.000Z",
    recordedAt: "2026-01-02T00:00:01.000Z",
    reason: "test",
    provenance: "test",
  };

  if (previousAuditHash !== undefined) {
    event.previousAuditHash = previousAuditHash;
  }

  return {
    ...event,
    recordHash: createAuditHash(event),
  };
}

test("valid evidence chain verifies", () => {
  const first = makeEvidence("evidence-001");
  const second = makeEvidence("evidence-002", evidenceHash(first));

  const result = verifyEvidenceChain([first, second]);

  assert.equal(result.valid, true);
  assert.equal(result.verifiedCount, 2);
});

test("tampered evidence record is detected", () => {
  const first = makeEvidence("evidence-001");
  const second = makeEvidence("evidence-002", evidenceHash(first));

  const tampered: Evidence = {
    ...second,
    contentHash: "ATTACKER-CONTENT",
  };

  const result = verifyEvidenceChain([first, tampered]);

  assert.equal(result.valid, false);
  assert.equal(result.reason, "RECORD_HASH_MISMATCH_AT_1");
});

test("tampered evidence record hash is detected", () => {
  const first = makeEvidence("evidence-001");
  const tampered: Evidence = {
    ...first,
    recordHash: "0".repeat(64),
  };

  const result = verifyEvidenceChain([tampered]);

  assert.equal(result.valid, false);
  assert.equal(result.reason, "RECORD_HASH_MISMATCH_AT_0");
});

test("incorrect evidence previous hash is detected", () => {
  const first = makeEvidence("evidence-001");
  const second = makeEvidence("evidence-002", "FORGED-PREVIOUS-HASH");

  const result = verifyEvidenceChain([first, second]);

  assert.equal(result.valid, false);
  assert.equal(result.reason, "PREVIOUS_HASH_MISMATCH_AT_1");
});

test("valid audit chain verifies", () => {
  const first = makeAudit("audit-001");
  const second = makeAudit("audit-002", auditHash(first));

  const result = verifyAuditChain([first, second]);

  assert.equal(result.valid, true);
  assert.equal(result.verifiedCount, 2);
  assert.ok(result.finalHash);
});

test("tampered audit record is detected", () => {
  const first = makeAudit("audit-001");

  const tampered: AuditEvent = {
    ...first,
    reason: "ATTACKER-CHANGED-REASON",
  };

  const result = verifyAuditChain([tampered]);

  assert.equal(result.valid, false);
  assert.equal(result.reason, "RECORD_HASH_MISMATCH_AT_0");
});

test("tampered audit record hash is detected", () => {
  const first = makeAudit("audit-001");

  const tampered: AuditEvent = {
    ...first,
    recordHash: "f".repeat(64),
  };

  const result = verifyAuditChain([tampered]);

  assert.equal(result.valid, false);
  assert.equal(result.reason, "RECORD_HASH_MISMATCH_AT_0");
});

test("incorrect audit previous hash is detected", () => {
  const first = makeAudit("audit-001");
  const second = makeAudit("audit-002", "FORGED-AUDIT-HASH");

  const result = verifyAuditChain([first, second]);

  assert.equal(result.valid, false);
  assert.equal(result.reason, "PREVIOUS_HASH_MISMATCH_AT_1");
});
