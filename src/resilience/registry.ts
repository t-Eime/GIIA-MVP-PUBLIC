import { DatabaseSync } from "node:sqlite";
import { verifyTransitionChain, verifyStateTransition as verifyStateTransitionIntegrity } from "./state.js";
import { verifyOfflineEvidence } from "./evidence.js";
import type { StateTransition, SystemState } from "./types.js";
import {
  verifyResilienceAuthorizationReceipt,
  type ResilienceAuthorizationReceipt,
} from "./authorization.js";

export interface PersistedResilienceState {
  state: SystemState;
  changedAt: string;
  reason: string;
  transitionHash?: string;
}

export interface OfflineEvidence {
  id: string;
  subjectId: string;
  recordedAt: string;
  evidenceType: string;
  payload: string;
  sequence: number;
  previousEvidenceHash?: string;
  evidenceHash: string;
  reconciled: boolean;
}

export interface ReconciliationConflict {
  id: string;
  subjectId: string;
  localEvidenceId: string;
  remoteEvidenceId: string;
  reason: string;
  detectedAt: string;
  resolved: boolean;
}

export class ResilienceRegistry {
  private readonly db: DatabaseSync;

  constructor(path = ".resilience.sqlite") {
    this.db = new DatabaseSync(path);

    this.db.exec(`
      PRAGMA journal_mode=WAL;

      CREATE TABLE IF NOT EXISTS resilience_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        state TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        reason TEXT NOT NULL,
        transition_hash TEXT
      );

      CREATE TABLE IF NOT EXISTS resilience_transitions (
        transition_hash TEXT PRIMARY KEY,
        transition_id TEXT NOT NULL UNIQUE,
        payload TEXT NOT NULL
      );

      CREATE TRIGGER IF NOT EXISTS resilience_transitions_immutable_update
      BEFORE UPDATE ON resilience_transitions
      BEGIN
        SELECT RAISE(ABORT, 'RESILIENCE_TRANSITION_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS resilience_transitions_append_only_delete
      BEFORE DELETE ON resilience_transitions
      BEGIN
        SELECT RAISE(ABORT, 'RESILIENCE_TRANSITION_APPEND_ONLY');
      END;

      CREATE TABLE IF NOT EXISTS resilience_authorization_receipts (
        receipt_hash TEXT PRIMARY KEY,
        receipt_id TEXT NOT NULL UNIQUE,
        transition_id TEXT NOT NULL UNIQUE,
        payload TEXT NOT NULL
      );

      CREATE TRIGGER IF NOT EXISTS resilience_receipts_immutable_update
      BEFORE UPDATE ON resilience_authorization_receipts
      BEGIN
        SELECT RAISE(ABORT, 'RESILIENCE_RECEIPT_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS resilience_receipts_append_only_delete
      BEFORE DELETE ON resilience_authorization_receipts
      BEGIN
        SELECT RAISE(ABORT, 'RESILIENCE_RECEIPT_APPEND_ONLY');
      END;

      CREATE TABLE IF NOT EXISTS offline_evidence (
        evidence_id TEXT PRIMARY KEY,
        subject_id TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        previous_evidence_hash TEXT,
        evidence_hash TEXT NOT NULL UNIQUE,
        reconciled INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS reconciliation_conflicts (
        conflict_id TEXT PRIMARY KEY,
        subject_id TEXT NOT NULL,
        local_evidence_id TEXT NOT NULL,
        remote_evidence_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        detected_at TEXT NOT NULL,
        resolved INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS recovery_markers (
        marker_id TEXT PRIMARY KEY,
        marker_type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        detail TEXT NOT NULL
      );

      CREATE TRIGGER IF NOT EXISTS offline_evidence_immutable_update
      BEFORE UPDATE ON offline_evidence
      BEGIN
        SELECT RAISE(ABORT, 'OFFLINE_EVIDENCE_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS offline_evidence_append_only_delete
      BEFORE DELETE ON offline_evidence
      BEGIN
        SELECT RAISE(ABORT, 'OFFLINE_EVIDENCE_APPEND_ONLY');
      END;

      CREATE TRIGGER IF NOT EXISTS reconciliation_conflicts_immutable_update
      BEFORE UPDATE ON reconciliation_conflicts
      BEGIN
        SELECT RAISE(ABORT, 'RECONCILIATION_CONFLICT_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS reconciliation_conflicts_append_only_delete
      BEFORE DELETE ON reconciliation_conflicts
      BEGIN
        SELECT RAISE(ABORT, 'RECONCILIATION_CONFLICT_APPEND_ONLY');
      END;

      CREATE TRIGGER IF NOT EXISTS recovery_markers_immutable_update
      BEFORE UPDATE ON recovery_markers
      BEGIN
        SELECT RAISE(ABORT, 'RECOVERY_MARKER_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS recovery_markers_append_only_delete
      BEFORE DELETE ON recovery_markers
      BEGIN
        SELECT RAISE(ABORT, 'RECOVERY_MARKER_APPEND_ONLY');
      END;
    `);
  }

  getAuthoritativeState(): SystemState {
    const persisted = this.getState();
    const transitions = this.listTransitions();

    if (transitions.length === 0) {
      if (persisted === undefined) {
        return "ONLINE";
      }

      throw new Error(
        "RESILIENCE_STATE_INTEGRITY_FAILURE",
      );
    }

    if (!verifyTransitionChain(transitions)) {
      throw new Error(
        "RESILIENCE_TRANSITION_CHAIN_INTEGRITY_FAILURE",
      );
    }

    const latest = transitions.at(-1)!;

    if (
      persisted === undefined ||
      persisted.state !== latest.to ||
      persisted.transitionHash !== latest.transitionHash
    ) {
      throw new Error(
        "RESILIENCE_STATE_INTEGRITY_FAILURE",
      );
    }

    return latest.to;
  }

  getState(): PersistedResilienceState | undefined {
    const row = this.db
      .prepare(`
        SELECT state, changed_at, reason, transition_hash
        FROM resilience_state
        WHERE id = 1
      `)
      .get() as {
        state?: SystemState;
        changed_at?: string;
        reason?: string;
        transition_hash?: string | null;
      } | undefined;

    if (!row?.state || !row.changed_at || !row.reason) {
      return undefined;
    }

    return {
      state: row.state,
      changedAt: row.changed_at,
      reason: row.reason,
      ...(row.transition_hash === null ||
      row.transition_hash === undefined
        ? {}
        : { transitionHash: row.transition_hash }),
    };
  }

  private commitTransition(
    transition: StateTransition,
    authorizationReceipt: ResilienceAuthorizationReceipt,
  ): void {
    if (
      !verifyResilienceAuthorizationReceipt(
        authorizationReceipt,
      )
    ) {
      throw new Error(
        "RESILIENCE_AUTHORIZATION_RECEIPT_INVALID",
      );
    }

    if (
      authorizationReceipt.intent.transitionId !==
      transition.id
    ) {
      throw new Error(
        "RESILIENCE_AUTHORIZATION_TRANSITION_MISMATCH",
      );
    }

    if (
      authorizationReceipt.intent.from !==
      transition.from ||
      authorizationReceipt.intent.to !==
      transition.to ||
      authorizationReceipt.intent.reason !==
      transition.reason ||
      authorizationReceipt.intent.action !==
      transition.action ||
      authorizationReceipt.intent.occurredAt !==
      transition.occurredAt ||
      authorizationReceipt.intent.evidenceRef !==
      transition.evidenceRef
    ) {
      throw new Error(
        "RESILIENCE_AUTHORIZATION_INTENT_MISMATCH",
      );
    }

    if (
      transition.authorizationReceiptHash !==
      authorizationReceipt.receiptHash
    ) {
      throw new Error(
        "RESILIENCE_AUTHORIZATION_RECEIPT_HASH_MISMATCH",
      );
    }

    if (
      authorizationReceipt.authority.id !==
      transition.authorityId
    ) {
      throw new Error(
        "RESILIENCE_AUTHORITY_BINDING_MISMATCH",
      );
    }

    this.db.exec("BEGIN IMMEDIATE");

    try {
      const existing = this.db
        .prepare(`
          SELECT transition_hash
          FROM resilience_transitions
          WHERE transition_id = ?
        `)
        .get(transition.id) as { transition_hash?: string } | undefined;

      if (existing?.transition_hash !== undefined) {
        throw new Error(
          `RESILIENCE_TRANSITION_ID_ALREADY_EXISTS:${transition.id}`,
        );
      }

      const currentTransitions =
        this.listTransitions();

      if (
        !verifyTransitionChain(currentTransitions)
      ) {
        throw new Error(
          "RESILIENCE_TRANSITION_CHAIN_INTEGRITY_FAILURE",
        );
      }

      const latest =
        currentTransitions.at(-1);

      if (
        latest !== undefined &&
        transition.previousTransitionHash !==
          latest.transitionHash
      ) {
        throw new Error(
          "RESILIENCE_STALE_TRANSITION_CHAIN",
        );
      }

      if (
        latest === undefined &&
        transition.previousTransitionHash !==
          undefined
      ) {
        throw new Error(
          "RESILIENCE_GENESIS_PREVIOUS_HASH_INVALID",
        );
      }

      this.db
        .prepare(`
          INSERT INTO resilience_authorization_receipts
            (receipt_hash, receipt_id, transition_id, payload)
          VALUES (?, ?, ?, ?)
        `)
        .run(
          authorizationReceipt.receiptHash,
          authorizationReceipt.id,
          transition.id,
          JSON.stringify(authorizationReceipt),
        );

      this.db
        .prepare(`
          INSERT INTO resilience_transitions
            (transition_hash, transition_id, payload)
          VALUES (?, ?, ?)
        `)
        .run(
          transition.transitionHash,
          transition.id,
          JSON.stringify(transition),
        );

      this.db
        .prepare(`
          INSERT INTO resilience_state
            (id, state, changed_at, reason, transition_hash)
          VALUES (1, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            state=excluded.state,
            changed_at=excluded.changed_at,
            reason=excluded.reason,
            transition_hash=excluded.transition_hash
        `)
        .run(
          transition.to,
          transition.occurredAt,
          transition.reason,
          transition.transitionHash,
        );

      this.db.exec("COMMIT");
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // Preserve the original failure.
      }
      throw error;
    }
  }

  authorizeTransitionCommit(
    transition: StateTransition,
    authorizationReceipt: ResilienceAuthorizationReceipt,
  ): void {
    this.commitTransition(transition, authorizationReceipt);
  }

  getAuthorizationReceipt(
    receiptHash: string,
  ): ResilienceAuthorizationReceipt | undefined {
    const row = this.db
      .prepare(`
        SELECT payload
        FROM resilience_authorization_receipts
        WHERE receipt_hash = ?
      `)
      .get(receiptHash) as { payload?: string } | undefined;

    if (row?.payload === undefined) {
      return undefined;
    }

    const receipt =
      JSON.parse(row.payload) as ResilienceAuthorizationReceipt;

    if (!verifyResilienceAuthorizationReceipt(receipt)) {
      throw new Error(
        "RESILIENCE_STORED_RECEIPT_INTEGRITY_FAILURE",
      );
    }

    return receipt;
  }

  listAuthorizationReceipts(): ResilienceAuthorizationReceipt[] {
    const rows = this.db
      .prepare(`
        SELECT payload
        FROM resilience_authorization_receipts
        ORDER BY rowid ASC
      `)
      .all() as Array<{ payload: string }>;

    return rows.map((row) => {
      const receipt =
        JSON.parse(row.payload) as ResilienceAuthorizationReceipt;

      if (!verifyResilienceAuthorizationReceipt(receipt)) {
        throw new Error(
          "RESILIENCE_STORED_RECEIPT_INTEGRITY_FAILURE",
        );
      }

      return receipt;
    });
  }

  listTransitions(): StateTransition[] {
    const rows = this.db
      .prepare(`
        SELECT payload
        FROM resilience_transitions
        ORDER BY rowid ASC
      `)
      .all() as Array<{ payload: string }>;

    return rows.map((row) => {
      const transition = JSON.parse(row.payload) as StateTransition;
      if (!verifyStateTransitionIntegrity(transition)) {
        throw new Error("RESILIENCE_STORED_TRANSITION_INTEGRITY_FAILURE");
      }
      return transition;
    });
  }

  putOfflineEvidence(evidence: OfflineEvidence): void {
    if (!verifyOfflineEvidence(evidence)) {
      throw new Error("OFFLINE_EVIDENCE_INTEGRITY_FAILURE");
    }

    const existing = this.db
      .prepare(`
        SELECT evidence_hash
        FROM offline_evidence
        WHERE evidence_id = ?
      `)
      .get(evidence.id) as {
        evidence_hash?: string;
      } | undefined;

    if (existing?.evidence_hash !== undefined) {
      throw new Error(
        `OFFLINE_EVIDENCE_ID_ALREADY_EXISTS:${evidence.id}`,
      );
    }

    this.db
      .prepare(`
        INSERT INTO offline_evidence
          (
            evidence_id,
            subject_id,
            recorded_at,
            evidence_type,
            payload,
            sequence,
            previous_evidence_hash,
            evidence_hash,
            reconciled
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        evidence.id,
        evidence.subjectId,
        evidence.recordedAt,
        evidence.evidenceType,
        evidence.payload,
        evidence.sequence,
        evidence.previousEvidenceHash ?? null,
        evidence.evidenceHash,
        evidence.reconciled ? 1 : 0,
      );
  }

  listOfflineEvidence(subjectId?: string): OfflineEvidence[] {
    const rows =
      subjectId === undefined
        ? this.db
            .prepare(`
              SELECT *
              FROM offline_evidence
              ORDER BY subject_id ASC, sequence ASC, rowid ASC
            `)
            .all()
        : this.db
            .prepare(`
              SELECT *
              FROM offline_evidence
              WHERE subject_id = ?
              ORDER BY sequence ASC, rowid ASC
            `)
            .all(subjectId);

    return (rows as Array<Record<string, unknown>>).map((row) => {
      const evidence: OfflineEvidence = {
        id: String(row.evidence_id),
        subjectId: String(row.subject_id),
        recordedAt: String(row.recorded_at),
        evidenceType: String(row.evidence_type),
        payload: String(row.payload),
        sequence: Number(row.sequence),
        ...(row.previous_evidence_hash === null
          ? {}
          : {
              previousEvidenceHash: String(
                row.previous_evidence_hash,
              ),
            }),
        evidenceHash: String(row.evidence_hash),
        reconciled: Number(row.reconciled) === 1,
      };

      if (!verifyOfflineEvidence(evidence)) {
        throw new Error(
          "OFFLINE_EVIDENCE_INTEGRITY_FAILURE",
        );
      }

      return evidence;
    });
  }

  markEvidenceReconciled(_id: string): never {
    throw new Error(
      "OFFLINE_EVIDENCE_IMMUTABLE: use append-only reconciliation evidence",
    );
  }

  putConflict(conflict: ReconciliationConflict): void {
    this.db
      .prepare(`
        INSERT INTO reconciliation_conflicts
          (
            conflict_id,
            subject_id,
            local_evidence_id,
            remote_evidence_id,
            reason,
            detected_at,
            resolved
          )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        conflict.id,
        conflict.subjectId,
        conflict.localEvidenceId,
        conflict.remoteEvidenceId,
        conflict.reason,
        conflict.detectedAt,
        conflict.resolved ? 1 : 0,
      );
  }

  listConflicts(): ReconciliationConflict[] {
    const rows = this.db
      .prepare(`
        SELECT *
        FROM reconciliation_conflicts
        ORDER BY rowid ASC
      `)
      .all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      id: String(row.conflict_id),
      subjectId: String(row.subject_id),
      localEvidenceId: String(row.local_evidence_id),
      remoteEvidenceId: String(row.remote_evidence_id),
      reason: String(row.reason),
      detectedAt: String(row.detected_at),
      resolved: Number(row.resolved) === 1,
    }));
  }

  putRecoveryMarker(
    id: string,
    type: string,
    createdAt: string,
    detail: string,
  ): void {
    this.db
      .prepare(`
        INSERT INTO recovery_markers
          (marker_id, marker_type, created_at, detail)
        VALUES (?, ?, ?, ?)
      `)
      .run(id, type, createdAt, detail);
  }

  listRecoveryMarkers(): Array<{
    id: string;
    type: string;
    createdAt: string;
    detail: string;
  }> {
    const rows = this.db
      .prepare(`
        SELECT marker_id, marker_type, created_at, detail
        FROM recovery_markers
        ORDER BY rowid ASC
      `)
      .all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      id: String(row.marker_id),
      type: String(row.marker_type),
      createdAt: String(row.created_at),
      detail: String(row.detail),
    }));
  }

  close(): void {
    this.db.close();
  }
}
