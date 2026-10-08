import { DatabaseSync } from "node:sqlite";
import { verifyEvidenceIntegrity } from "../evidence/service.js";
import type { Evidence } from "../evidence/types.js";
import { verifyAuditIntegrity } from "../audit/service.js";
import type { AuditEvent } from "../audit/types.js";

export class EvidenceAuditRegistry {
  private readonly db: DatabaseSync;

  constructor(path = ".evidence-audit.sqlite") {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode=WAL;

      CREATE TABLE IF NOT EXISTS evidence_records (
        evidence_id TEXT PRIMARY KEY,
        authorization_request_id TEXT,
        action TEXT NOT NULL,
        subject TEXT NOT NULL,
        record_hash TEXT NOT NULL UNIQUE,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_records (
        audit_id TEXT PRIMARY KEY,
        authorization_request_id TEXT,
        evidence_id TEXT,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        record_hash TEXT NOT NULL UNIQUE,
        payload TEXT NOT NULL
      );

      CREATE TRIGGER IF NOT EXISTS evidence_records_no_update
      BEFORE UPDATE ON evidence_records
      BEGIN
        SELECT RAISE(ABORT, 'EVIDENCE_RECORD_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS evidence_records_no_delete
      BEFORE DELETE ON evidence_records
      BEGIN
        SELECT RAISE(ABORT, 'EVIDENCE_RECORD_APPEND_ONLY');
      END;

      CREATE TRIGGER IF NOT EXISTS audit_records_no_update
      BEFORE UPDATE ON audit_records
      BEGIN
        SELECT RAISE(ABORT, 'AUDIT_RECORD_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS audit_records_no_delete
      BEFORE DELETE ON audit_records
      BEGIN
        SELECT RAISE(ABORT, 'AUDIT_RECORD_APPEND_ONLY');
      END;
    `);
  }

  commitEvidenceAndAudit(evidence: Evidence, audit: AuditEvent): void {
    if (!verifyEvidenceIntegrity(evidence)) {
      throw new Error("EVIDENCE_INTEGRITY_INVALID");
    }

    if (!verifyAuditIntegrity(audit)) {
      throw new Error("AUDIT_INTEGRITY_INVALID");
    }

    if (
      evidence.authorizationRequestId !== audit.authorizationRequestId ||
      audit.evidenceId !== evidence.id ||
      audit.action !== evidence.action
    ) {
      throw new Error("EVIDENCE_AUDIT_BINDING_INVALID");
    }

    this.db.exec("BEGIN IMMEDIATE");

    try {
      const evidenceExists = this.db
        .prepare(`
          SELECT evidence_id
          FROM evidence_records
          WHERE evidence_id = ?
        `)
        .get(evidence.id) as { evidence_id?: string } | undefined;

      if (evidenceExists?.evidence_id !== undefined) {
        throw new Error(`EVIDENCE_ID_ALREADY_EXISTS:${evidence.id}`);
      }

      const auditExists = this.db
        .prepare(`
          SELECT audit_id
          FROM audit_records
          WHERE audit_id = ?
        `)
        .get(audit.id) as { audit_id?: string } | undefined;

      if (auditExists?.audit_id !== undefined) {
        throw new Error(`AUDIT_ID_ALREADY_EXISTS:${audit.id}`);
      }

      this.db
        .prepare(`
          INSERT INTO evidence_records
            (evidence_id, authorization_request_id, action, subject, record_hash, payload)
          VALUES (?, ?, ?, ?, ?, ?)
        `)
        .run(
          evidence.id,
          evidence.authorizationRequestId ?? null,
          evidence.action,
          evidence.subject,
          evidence.recordHash,
          JSON.stringify(evidence),
        );

      this.db
        .prepare(`
          INSERT INTO audit_records
            (audit_id, authorization_request_id, evidence_id, action, resource, record_hash, payload)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          audit.id,
          audit.authorizationRequestId ?? null,
          audit.evidenceId ?? null,
          audit.action,
          audit.resource,
          audit.recordHash,
          JSON.stringify(audit),
        );

      this.db.exec("COMMIT");
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // Preserve the original failure. The transaction is fail-closed.
      }
      throw error;
    }
  }

  getEvidence(id: string): Evidence | undefined {
    const row = this.db
      .prepare(`
          SELECT payload
          FROM evidence_records
          WHERE evidence_id = ?
        `)
      .get(id) as { payload?: string } | undefined;

    if (row?.payload === undefined) {
      return undefined;
    }

    const evidence = JSON.parse(row.payload) as Evidence;

    if (!verifyEvidenceIntegrity(evidence)) {
      throw new Error("EVIDENCE_INTEGRITY_INVALID");
    }

    return evidence;
  }

  getAudit(id: string): AuditEvent | undefined {
    const row = this.db
      .prepare(`
          SELECT payload
          FROM audit_records
          WHERE audit_id = ?
        `)
      .get(id) as { payload?: string } | undefined;

    if (row?.payload === undefined) {
      return undefined;
    }

    const audit = JSON.parse(row.payload) as AuditEvent;

    if (!verifyAuditIntegrity(audit)) {
      throw new Error("AUDIT_INTEGRITY_INVALID");
    }

    return audit;
  }

  countEvidence(): number {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS count FROM evidence_records`)
      .get() as { count?: number | bigint } | undefined;

    return Number(row?.count ?? 0);
  }

  countAudit(): number {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS count FROM audit_records`)
      .get() as { count?: number | bigint } | undefined;

    return Number(row?.count ?? 0);
  }

  close(): void {
    this.db.close();
  }
}
