import { DatabaseSync } from "node:sqlite";
import type {
  ConstitutionalRevocation,
  ConstitutionalRule,
} from "./types.js";

export class ConstitutionalRegistry {
  private readonly db: DatabaseSync;
  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS constitutional_rules (
        id TEXT PRIMARY KEY,
        version TEXT NOT NULL,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS constitutional_revocations (
        rule_id TEXT PRIMARY KEY,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS constitutional_replay (
        request_id TEXT PRIMARY KEY,
        consumed_at TEXT NOT NULL
      );
    `);
  }
  putRule(rule: ConstitutionalRule): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO constitutional_rules(id,version,payload) VALUES(?,?,?)",
      )
      .run(
        rule.id,
        rule.version,
        JSON.stringify(rule),
      );
  }

  private hydrateRule(payload: string): ConstitutionalRule {
    const rule = JSON.parse(payload) as ConstitutionalRule;

    if (this.isRevoked(rule.id)) {
      return {
        ...rule,
        status: "revoked",
      };
    }

    return rule;
  }
  getRule(id: string): ConstitutionalRule | undefined {
    const row = this.db
      .prepare("SELECT payload FROM constitutional_rules WHERE id=?")
      .get(id) as { payload?: string } | undefined;

    return row?.payload ? this.hydrateRule(row.payload) : undefined;
  }

  listRules(): ConstitutionalRule[] {
    const rows = this.db
      .prepare("SELECT payload FROM constitutional_rules ORDER BY id")
      .all() as Array<{ payload: string }>;

    return rows.map((row) => this.hydrateRule(row.payload));
  }
  revoke(revocation: ConstitutionalRevocation): void {
    this.db
      .prepare("INSERT OR REPLACE INTO constitutional_revocations(rule_id,payload) VALUES(?,?)")
      .run(revocation.ruleId, JSON.stringify(revocation));
  }

  isRevoked(ruleId: string): boolean {
    const row = this.db
      .prepare("SELECT rule_id FROM constitutional_revocations WHERE rule_id=?")
      .get(ruleId) as { rule_id?: string } | undefined;

    return row?.rule_id === ruleId;
  }
  consumeReplay(requestId: string, consumedAt: string): boolean {
    const result = this.db
      .prepare("INSERT OR IGNORE INTO constitutional_replay(request_id,consumed_at) VALUES(?,?)")
      .run(requestId, consumedAt);

    return result.changes === 1;
  }

  close(): void {
    this.db.close();
  }
}
