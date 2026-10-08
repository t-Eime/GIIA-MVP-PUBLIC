import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
  unlinkSync,
} from "node:fs";
import { dirname } from "node:path";

export interface ExternalReplayStore {
  has(authorizationId: string): boolean;
  record(authorizationId: string): void;
  consume(authorizationId: string): boolean;
}

export class DurableExternalReplayStore implements ExternalReplayStore {
  private readonly ids = new Set<string>();

  constructor(private readonly filePath: string) {
    this.load();
  }

  has(authorizationId: string): boolean {
    return this.ids.has(authorizationId);
  }

  record(authorizationId: string): void {
    if (this.ids.has(authorizationId)) {
      return;
    }

    this.ids.add(authorizationId);
    this.persist();
  }

  consume(authorizationId: string): boolean {
    const lockPath = `${this.filePath}.lock`;

    let acquired = false;

    try {
      try {
        writeFileSync(lockPath, "", {
          encoding: "utf8",
          flag: "wx",
          mode: 0o600,
        });
        acquired = true;
      } catch {
        return false;
      }

      this.load();

      if (this.ids.has(authorizationId)) {
        return false;
      }

      this.ids.add(authorizationId);
      this.persist();
      return true;
    } finally {
      if (acquired) {
        try {
          unlinkSync(lockPath);
        } catch {
          // Best-effort lock cleanup.
        }
      }
    }
  }

  private load(): void {
    if (!existsSync(this.filePath)) {
      return;
    }

    const raw = readFileSync(this.filePath, "utf8").trim();

    if (!raw) {
      return;
    }

    const parsed: unknown = JSON.parse(raw);

    if (!Array.isArray(parsed)) {
      throw new Error("EXTERNAL_REPLAY_STATE_INVALID");
    }

    for (const value of parsed) {
      if (typeof value !== "string" || value.length === 0) {
        throw new Error("EXTERNAL_REPLAY_STATE_INVALID");
      }

      this.ids.add(value);
    }
  }

  private persist(): void {
    mkdirSync(dirname(this.filePath), { recursive: true });

    const temporary = `${this.filePath}.tmp`;

    writeFileSync(
      temporary,
      JSON.stringify([...this.ids].sort(), null, 2),
      {
        encoding: "utf8",
        mode: 0o600,
      },
    );

    renameSync(temporary, this.filePath);
  }
}

export class MemoryExternalReplayStore implements ExternalReplayStore {
  private readonly ids = new Set<string>();

  has(authorizationId: string): boolean {
    return this.ids.has(authorizationId);
  }

  record(authorizationId: string): void {
    this.ids.add(authorizationId);
  }

  consume(authorizationId: string): boolean {
    if (this.ids.has(authorizationId)) {
      return false;
    }

    this.ids.add(authorizationId);
    return true;
  }
}
