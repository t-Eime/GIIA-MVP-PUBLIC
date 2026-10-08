import { canonicalize } from "../core/canonical.js";
import { DatabaseSync } from "node:sqlite";
import type {
  TrustAnchor,
  TrustCredential,
  TrustDelegation,
  TrustKey,
  TrustRoot,
  TrustRevocation,
} from "./types.js";

export class TrustRegistry {
  private readonly db: DatabaseSync;

  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS trust_keys (
        id TEXT PRIMARY KEY,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS trust_roots (
        id TEXT PRIMARY KEY,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS trust_anchors (
        id TEXT PRIMARY KEY,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS trust_delegations (
        id TEXT PRIMARY KEY,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS trust_credentials (
        id TEXT PRIMARY KEY,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS trust_revocations (
        object_type TEXT NOT NULL,
        object_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        PRIMARY KEY(object_type, object_id)
      );

      CREATE TABLE IF NOT EXISTS trust_replay (
        request_id TEXT PRIMARY KEY,
        consumed_at TEXT NOT NULL
      );
    `);
  }

  ensureKey(value: TrustKey): void {
    const existing = this.getKey(value.id);

    if (!existing) {
      this.putKey(value);
      return;
    }

    if (canonicalize(existing) !== canonicalize(value)) {
      throw new Error("DURABLE_TRUST_STATE_MISMATCH");
    }
  }

  ensureRoot(value: TrustRoot): void {
    const existing = this.getRoot(value.id);

    if (!existing) {
      this.putRoot(value);
      return;
    }

    if (canonicalize(existing) !== canonicalize(value)) {
      throw new Error("DURABLE_TRUST_STATE_MISMATCH");
    }
  }

  ensureAnchor(value: TrustAnchor): void {
    const existing = this.getAnchor(value.id);

    if (!existing) {
      this.putAnchor(value);
      return;
    }

    if (canonicalize(existing) !== canonicalize(value)) {
      throw new Error("DURABLE_TRUST_STATE_MISMATCH");
    }
  }

  ensureDelegation(value: TrustDelegation): void {
    const existing = this.getDelegation(value.id);

    if (!existing) {
      this.putDelegation(value);
      return;
    }

    if (canonicalize(existing) !== canonicalize(value)) {
      throw new Error("DURABLE_TRUST_STATE_MISMATCH");
    }
  }

  ensureCredential(value: TrustCredential): void {
    const existing = this.getCredential(value.id);

    if (!existing) {
      this.putCredential(value);
      return;
    }

    if (canonicalize(existing) !== canonicalize(value)) {
      throw new Error("DURABLE_TRUST_STATE_MISMATCH");
    }
  }

  putKey(value: TrustKey): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO trust_keys(id,payload) VALUES(?,?)",
      )
      .run(value.id, JSON.stringify(value));
  }

  getKey(id: string): TrustKey | undefined {
    const row = this.db
      .prepare("SELECT payload FROM trust_keys WHERE id=?")
      .get(id) as { payload?: string } | undefined;

    return row?.payload
      ? JSON.parse(row.payload) as TrustKey
      : undefined;
  }

  putRoot(value: TrustRoot): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO trust_roots(id,payload) VALUES(?,?)",
      )
      .run(value.id, JSON.stringify(value));
  }

  getRoot(id: string): TrustRoot | undefined {
    const row = this.db
      .prepare("SELECT payload FROM trust_roots WHERE id=?")
      .get(id) as { payload?: string } | undefined;

    return row?.payload
      ? JSON.parse(row.payload) as TrustRoot
      : undefined;
  }

  putAnchor(value: TrustAnchor): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO trust_anchors(id,payload) VALUES(?,?)",
      )
      .run(value.id, JSON.stringify(value));
  }

  getAnchor(id: string): TrustAnchor | undefined {
    const row = this.db
      .prepare("SELECT payload FROM trust_anchors WHERE id=?")
      .get(id) as { payload?: string } | undefined;

    return row?.payload
      ? JSON.parse(row.payload) as TrustAnchor
      : undefined;
  }

  putDelegation(value: TrustDelegation): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO trust_delegations(id,payload) VALUES(?,?)",
      )
      .run(value.id, JSON.stringify(value));
  }

  getDelegation(id: string): TrustDelegation | undefined {
    const row = this.db
      .prepare("SELECT payload FROM trust_delegations WHERE id=?")
      .get(id) as { payload?: string } | undefined;

    return row?.payload
      ? JSON.parse(row.payload) as TrustDelegation
      : undefined;
  }

  putCredential(value: TrustCredential): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO trust_credentials(id,payload) VALUES(?,?)",
      )
      .run(value.id, JSON.stringify(value));
  }

  getCredential(id: string): TrustCredential | undefined {
    const row = this.db
      .prepare("SELECT payload FROM trust_credentials WHERE id=?")
      .get(id) as { payload?: string } | undefined;

    return row?.payload
      ? JSON.parse(row.payload) as TrustCredential
      : undefined;
  }

  revoke(value: TrustRevocation): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO trust_revocations(object_type,object_id,payload) VALUES(?,?,?)",
      )
      .run(
        value.objectType,
        value.objectId,
        JSON.stringify(value),
      );
  }

  isRevoked(
    objectType: TrustRevocation["objectType"],
    objectId: string,
  ): boolean {
    const row = this.db
      .prepare(
        "SELECT object_id FROM trust_revocations WHERE object_type=? AND object_id=?",
      )
      .get(objectType, objectId) as { object_id?: string } | undefined;

    return row?.object_id === objectId;
  }

  consumeReplay(requestId: string, consumedAt: string): boolean {
    const result = this.db
      .prepare(
        "INSERT OR IGNORE INTO trust_replay(request_id,consumed_at) VALUES(?,?)",
      )
      .run(requestId, consumedAt);

    return result.changes === 1;
  }

  close(): void {
    this.db.close();
  }
}
