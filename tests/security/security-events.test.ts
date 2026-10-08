import test from "node:test";
import assert from "node:assert/strict";
import { unlinkSync } from "node:fs";

import {
  createSecurityEvent,
  verifySecurityEvent,
  verifySecurityEventChain,
} from "../../src/security/events.js";
import { SecurityRegistry } from "../../src/security/registry.js";
import { SecurityService } from "../../src/security/service.js";
import { GIIAError } from "../../src/core/errors.js";

const NOW = "2026-01-02T00:00:00.000Z";
const LATER = "2026-01-02T00:00:01.000Z";

function removeDatabase(path: string): void {
  for (const suffix of ["", "-shm", "-wal"]) {
    try {
      unlinkSync(`${path}${suffix}`);
    } catch {
      // File may not exist.
    }
  }
}

function expectError(
  fn: () => unknown,
  code: string,
): void {
  assert.throws(fn, (error: unknown) => {
    return (
      error instanceof GIIAError &&
      error.code === code
    );
  });
}

test("security event hash verifies", () => {
  const event = createSecurityEvent({
    id: "security-001",
    type: "INTEGRITY_VIOLATION",
    severity: "HIGH",
    subjectId: "key-001",
    detectedAt: NOW,
    source: "test",
    reason: "tamper detected",
    provenance: "test",
    containment: "NONE",
  });

  assert.equal(verifySecurityEvent(event), true);
});

test("security event chain verifies", () => {
  const first = createSecurityEvent({
    id: "security-001",
    type: "INTEGRITY_VIOLATION",
    severity: "HIGH",
    subjectId: "key-001",
    detectedAt: NOW,
    source: "test",
    reason: "tamper detected",
    provenance: "test",
    containment: "NONE",
  });

  const second = createSecurityEvent({
    id: "security-002",
    type: "KEY_COMPROMISE_SUSPECTED",
    severity: "HIGH",
    subjectId: "key-001",
    detectedAt: LATER,
    source: "test",
    reason: "repeated integrity failure",
    provenance: "test",
    containment: "QUARANTINED",
    previousEventHash: first.eventHash,
  });

  const result = verifySecurityEventChain([
    first,
    second,
  ]);

  assert.equal(result.valid, true);
  assert.equal(result.verifiedCount, 2);
});

test("tampered security event is detected", () => {
  const event = createSecurityEvent({
    id: "security-001",
    type: "INTEGRITY_VIOLATION",
    severity: "HIGH",
    subjectId: "key-001",
    detectedAt: NOW,
    source: "test",
    reason: "tamper detected",
    provenance: "test",
    containment: "NONE",
  });

  const tampered = {
    ...event,
    reason: "ATTACKER-MODIFIED",
  };

  const result = verifySecurityEventChain([tampered]);

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "EVENT_HASH_MISMATCH_AT_0",
  );
});

test("forged previous security event hash is detected", () => {
  const first = createSecurityEvent({
    id: "security-001",
    type: "INTEGRITY_VIOLATION",
    severity: "HIGH",
    subjectId: "key-001",
    detectedAt: NOW,
    source: "test",
    reason: "tamper detected",
    provenance: "test",
    containment: "NONE",
  });

  const second = createSecurityEvent({
    id: "security-002",
    type: "KEY_COMPROMISE_SUSPECTED",
    severity: "HIGH",
    subjectId: "key-001",
    detectedAt: LATER,
    source: "test",
    reason: "repeated integrity failure",
    provenance: "test",
    containment: "QUARANTINED",
    previousEventHash: "FORGED",
  });

  const result = verifySecurityEventChain([
    first,
    second,
  ]);

  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    "PREVIOUS_EVENT_HASH_MISMATCH_AT_1",
  );
});

test("replay protection is durable", () => {
  const path = ".test-security-events.sqlite";

  removeDatabase(path);

  const firstRegistry = new SecurityRegistry(path);

  assert.equal(
    firstRegistry.consumeReplay("request-001", NOW),
    true,
  );

  firstRegistry.close();

  const secondRegistry = new SecurityRegistry(path);

  assert.equal(
    secondRegistry.consumeReplay("request-001", LATER),
    false,
  );

  secondRegistry.close();

  removeDatabase(path);
});

test("security detection is persisted and chained", () => {
  const registry = new SecurityRegistry();
  const service = new SecurityService(registry);

  service.recordDetection({
    id: "security-001",
    type: "REPLAY_DETECTED",
    severity: "HIGH",
    subjectId: "request-001",
    detectedAt: NOW,
    source: "test",
    reason: "duplicate request",
    provenance: "test",
  });

  service.recordDetection({
    id: "security-002",
    type: "INTEGRITY_VIOLATION",
    severity: "CRITICAL",
    subjectId: "key-001",
    detectedAt: LATER,
    source: "test",
    reason: "record hash mismatch",
    provenance: "test",
  });

  assert.equal(service.events().length, 2);
  assert.equal(service.verifyEventChain().valid, true);

  registry.close();
});

test("quarantine changes subject state", () => {
  const registry = new SecurityRegistry();
  const service = new SecurityService(registry);

  const event = service.quarantineSubject(
    "key-001",
    NOW,
    "suspected compromise",
  );

  assert.equal(event.containment, "QUARANTINED");
  assert.equal(
    service.getSubjectState("key-001")?.state,
    "QUARANTINED",
  );

  registry.close();
});

test("containment changes subject state", () => {
  const registry = new SecurityRegistry();
  const service = new SecurityService(registry);

  const event = service.containSubject(
    "key-001",
    NOW,
    "confirmed compromise",
  );

  assert.equal(event.type, "CONTAINMENT_ACTIVATED");
  assert.equal(
    service.getSubjectState("key-001")?.state,
    "CONTAINED",
  );

  registry.close();
});

test("release requires quarantine or containment", () => {
  const registry = new SecurityRegistry();
  const service = new SecurityService(registry);

  expectError(
    () =>
      service.releaseSubject(
        "key-001",
        NOW,
        "unauthorized release",
      ),
    "SECURITY_RELEASE_REQUIRES_CONTAINMENT",
  );

  registry.close();
});

test("contained subject can be released", () => {
  const registry = new SecurityRegistry();
  const service = new SecurityService(registry);

  service.containSubject(
    "key-001",
    NOW,
    "confirmed compromise",
  );

  const event = service.releaseSubject(
    "key-001",
    LATER,
    "independent verification completed",
  );

  assert.equal(
    event.type,
    "CONTAINMENT_RELEASED",
  );

  assert.equal(
    service.getSubjectState("key-001")?.state,
    "ACTIVE",
  );

  registry.close();
});

test("security event records are append-only", () => {
  const registry = new SecurityRegistry();

  const event = createSecurityEvent({
    id: "security-immutable-001",
    type: "INTEGRITY_VIOLATION",
    severity: "HIGH",
    subjectId: "key-immutable-001",
    detectedAt: NOW,
    source: "test",
    reason: "original event",
    provenance: "test",
    containment: "NONE",
  });

  registry.putEvent(event);

  assert.throws(
    () =>
      registry.putEvent({
        ...event,
        reason: "ATTACKER-REPLACED-EVENT",
        eventHash: "FORGED-HASH",
      }),
    /SECURITY_EVENT_ID_ALREADY_EXISTS/,
  );

  const stored = registry.getEvent(event.id);

  assert.ok(stored);
  assert.equal(stored.reason, "original event");
  assert.equal(stored.eventHash, event.eventHash);

  registry.close();
});

test("replay attempt creates security evidence", () => {
  const registry = new SecurityRegistry();
  const service = new SecurityService(registry);

  assert.equal(
    service.consumeReplay("request-replay-001", NOW),
    true,
  );

  assert.equal(
    service.consumeReplay("request-replay-001", LATER),
    false,
  );

  const events = service.events();

  assert.equal(events.length, 1);
  assert.equal(events[0]?.type, "REPLAY_DETECTED");
  assert.equal(events[0]?.subjectId, "request-replay-001");
  assert.equal(service.verifyEventChain().valid, true);

  registry.close();
});
