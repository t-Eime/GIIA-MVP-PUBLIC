import { DatabaseSync } from "node:sqlite";
import type { SecurityEvent } from "./events.js";

export class SecurityRegistry {
  private readonly db: DatabaseSync;

  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS security_events (
        id TEXT PRIMARY KEY,
        event_hash TEXT NOT NULL,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS security_replay (
        request_id TEXT PRIMARY KEY,
        consumed_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS security_subject_state (
        subject_id TEXT PRIMARY KEY,
        state TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        reason TEXT NOT NULL
      );
    `);
  }

  putEvent(event: SecurityEvent): void {
    const existing = this.db
      .prepare("SELECT event_hash FROM security_events WHERE id=?")
      .get(event.id) as { event_hash?: string } | undefined;

    if (existing?.event_hash !== undefined) {
      throw new Error(
        `SECURITY_EVENT_ID_ALREADY_EXISTS:${event.id}`,
      );
    }

    this.db
      .prepare(
        "INSERT INTO security_events(id,event_hash,payload) VALUES(?,?,?)",
      )
      .run(
        event.id,
        event.eventHash,
        JSON.stringify(event),
      );
  }

  getEvent(id: string): SecurityEvent | undefined {
    const row = this.db
      .prepare(
        "SELECT payload FROM security_events WHERE id=?",
      )
      .get(id) as { payload?: string } | undefined;

    return row?.payload
      ? (JSON.parse(row.payload) as SecurityEvent)
      : undefined;
  }

  listEvents(): SecurityEvent[] {
    const rows = this.db
      .prepare(
        "SELECT payload FROM security_events ORDER BY rowid ASC",
      )
      .all() as Array<{ payload: string }>;

    return rows.map(
      (row) => JSON.parse(row.payload) as SecurityEvent,
    );
  }

  consumeReplay(
    requestId: string,
    consumedAt: string,
  ): boolean {
    const result = this.db
      .prepare(
        "INSERT OR IGNORE INTO security_replay(request_id,consumed_at) VALUES(?,?)",
      )
      .run(requestId, consumedAt);

    return result.changes === 1;
  }

  setSubjectState(
    subjectId: string,
    state: "ACTIVE" | "QUARANTINED" | "CONTAINED",
    changedAt: string,
    reason: string,
  ): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO security_subject_state
         (subject_id,state,changed_at,reason)
         VALUES(?,?,?,?)`,
      )
      .run(subjectId, state, changedAt, reason);
  }

  getSubjectState(
    subjectId: string,
  ):
    | {
        subjectId: string;
        state: "ACTIVE" | "QUARANTINED" | "CONTAINED";
        changedAt: string;
        reason: string;
      }
    | undefined {
    const row = this.db
      .prepare(
        `SELECT subject_id,state,changed_at,reason
         FROM security_subject_state
         WHERE subject_id=?`,
      )
      .get(subjectId) as
      | {
          subject_id?: string;
          state?: "ACTIVE" | "QUARANTINED" | "CONTAINED";
          changed_at?: string;
          reason?: string;
        }
      | undefined;

    if (
      !row?.subject_id ||
      !row.state ||
      !row.changed_at ||
      !row.reason
    ) {
      return undefined;
    }

    return {
      subjectId: row.subject_id,
      state: row.state,
      changedAt: row.changed_at,
      reason: row.reason,
    };
  }

  close(): void {
    this.db.close();
  }
}
