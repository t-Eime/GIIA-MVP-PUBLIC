import { invariant } from "../core/errors.js";
import {
  createSecurityEvent,
  type ContainmentState,
  type SecurityEvent,
  type SecurityEventType,
  type SecuritySeverity,
  verifySecurityEventChain,
} from "./events.js";
import { SecurityRegistry } from "./registry.js";
import { KeySecurityBoundary } from "./key-boundary.js";

export interface SecurityDetectionInput {
  id: string;
  type: SecurityEventType;
  severity: SecuritySeverity;
  subjectId: string;
  detectedAt: string;
  source: string;
  reason: string;
  provenance: string;
}

export class SecurityService {
  constructor(
    private readonly registry: SecurityRegistry,
    private readonly keyBoundary?: KeySecurityBoundary,
  ) {}

  consumeReplay(
    requestId: string,
    at: string,
  ): boolean {
    const accepted = this.registry.consumeReplay(requestId, at);

    if (!accepted) {
      const previous =
        this.registry.listEvents().at(-1)?.eventHash;

      const event = createSecurityEvent({
        id: `replay-${requestId}-${at}`,
        type: "REPLAY_DETECTED",
        severity: "HIGH",
        subjectId: requestId,
        detectedAt: at,
        source: "security-replay-protection",
        reason: "Previously consumed request identifier was presented again",
        provenance: "GIIA",
        containment: "NONE",
        ...(previous === undefined
          ? {}
          : { previousEventHash: previous }),
      });

      this.registry.putEvent(event);
    }

    return accepted;
  }

  recordDetection(
    input: SecurityDetectionInput,
  ): SecurityEvent {
    const previous = this.registry.listEvents().at(-1)?.eventHash;

    const event = createSecurityEvent({
      ...input,
      containment: "NONE",
      ...(previous === undefined
        ? {}
        : { previousEventHash: previous }),
    });

    this.registry.putEvent(event);

    return event;
  }

  quarantineSubject(
    subjectId: string,
    at: string,
    reason: string,
  ): SecurityEvent {
    this.registry.setSubjectState(
      subjectId,
      "QUARANTINED",
      at,
      reason,
    );

    if (this.keyBoundary?.hasPrivateMaterial(subjectId)) {
      this.keyBoundary.quarantine(subjectId, at, reason);
    }

    const previous = this.registry.listEvents().at(-1)?.eventHash;

    const event = createSecurityEvent({
      id: `quarantine-${subjectId}-${at}`,
      type: "KEY_QUARANTINED",
      severity: "HIGH",
      subjectId,
      detectedAt: at,
      source: "security-containment",
      reason,
      provenance: "GIIA",
      containment: "QUARANTINED",
      ...(previous === undefined
        ? {}
        : { previousEventHash: previous }),
    });

    this.registry.putEvent(event);

    return event;
  }

  containSubject(
    subjectId: string,
    at: string,
    reason: string,
  ): SecurityEvent {
    this.registry.setSubjectState(
      subjectId,
      "CONTAINED",
      at,
      reason,
    );

    const previous = this.registry.listEvents().at(-1)?.eventHash;

    const event = createSecurityEvent({
      id: `contain-${subjectId}-${at}`,
      type: "CONTAINMENT_ACTIVATED",
      severity: "CRITICAL",
      subjectId,
      detectedAt: at,
      source: "security-containment",
      reason,
      provenance: "GIIA",
      containment: "CONTAINED",
      ...(previous === undefined
        ? {}
        : { previousEventHash: previous }),
    });

    this.registry.putEvent(event);

    return event;
  }

  releaseSubject(
    subjectId: string,
    at: string,
    reason: string,
  ): SecurityEvent {
    const current = this.registry.getSubjectState(subjectId);

    invariant(
      current?.state === "CONTAINED" ||
        current?.state === "QUARANTINED",
      "SECURITY_RELEASE_REQUIRES_CONTAINMENT",
      `Subject ${subjectId} is not contained or quarantined`,
    );

    this.registry.setSubjectState(
      subjectId,
      "ACTIVE",
      at,
      reason,
    );

    const previous = this.registry.listEvents().at(-1)?.eventHash;

    const event = createSecurityEvent({
      id: `release-${subjectId}-${at}`,
      type: "CONTAINMENT_RELEASED",
      severity: "HIGH",
      subjectId,
      detectedAt: at,
      source: "security-containment",
      reason,
      provenance: "GIIA",
      containment: "RELEASED",
      ...(previous === undefined
        ? {}
        : { previousEventHash: previous }),
    });

    this.registry.putEvent(event);

    return event;
  }

  getSubjectState(subjectId: string) {
    return this.registry.getSubjectState(subjectId);
  }

  events(): SecurityEvent[] {
    return this.registry.listEvents();
  }

  verifyEventChain() {
    return verifySecurityEventChain(this.registry.listEvents());
  }
}
