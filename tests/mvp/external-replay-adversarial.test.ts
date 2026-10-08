import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { DurableExternalReplayStore } from "../../external-mvp/replay-store.js";

function temporaryPath(name: string): string {
  const dir = join(
    tmpdir(),
    `giia-p02-replay-${process.pid}-${Date.now()}-${Math.random()
      .toString(16)
      .slice(2)}`,
  );

  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

function cleanup(filePath: string): void {
  for (const path of [
    filePath,
    `${filePath}.lock`,
    `${filePath}.tmp`,
  ]) {
    try {
      unlinkSync(path);
    } catch {
      // Best effort test cleanup.
    }
  }
}

function runChild(
  modulePath: string,
  replayFile: string,
  authorizationId: string,
): Promise<{
  result: boolean;
  pid: number;
}> {
  const script = `
    import { DurableExternalReplayStore } from ${JSON.stringify(
      modulePath,
    )};

    const store = new DurableExternalReplayStore(
      process.env.GIIA_REPLAY_FILE
    );

    let result = false;

    try {
      result = store.consume(
        process.env.GIIA_AUTHORIZATION_ID
      );
    } catch (error) {
      console.error(
        error instanceof Error ? error.message : String(error)
      );
      process.exit(2);
    }

    console.log(
      JSON.stringify({
        result,
        pid: process.pid,
      })
    );

    process.exit(result ? 0 : 1);
  `;

  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--input-type=module", "--eval", script],
      {
        env: {
          ...process.env,
          GIIA_REPLAY_FILE: replayFile,
          GIIA_AUTHORIZATION_ID: authorizationId,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.on("error", reject);

    child.on("close", (code) => {
      if (code !== 0 && code !== 1) {
        reject(
          new Error(
            `child process failed: code=${code} stderr=${stderr}`,
          ),
        );
        return;
      }

      try {
        resolve(JSON.parse(stdout.trim()));
      } catch {
        reject(
          new Error(
            `invalid child output: ${stdout} stderr=${stderr}`,
          ),
        );
      }
    });
  });
}

test(
  "durable replay permits exactly one concurrent cross-process consume",
  async () => {
    const replayFile = temporaryPath("replay.json");
    const modulePath = join(
      process.cwd(),
      "dist/external-mvp/replay-store.js",
    );

    try {
      const children = Array.from({ length: 32 }, () =>
        runChild(
          modulePath,
          replayFile,
          "P0.2-CONCURRENT-AUTH-001",
        ),
      );

      const results = await Promise.all(children);

      const successes = results.filter(
        (result) => result.result === true,
      );

      const failures = results.filter(
        (result) => result.result === false,
      );

      assert.equal(successes.length, 1);
      assert.equal(failures.length, 31);

      assert.ok(existsSync(replayFile));

      const durable = JSON.parse(
        readFileSync(replayFile, "utf8"),
      );

      assert.deepEqual(durable, [
        "P0.2-CONCURRENT-AUTH-001",
      ]);

      assert.equal(
        existsSync(`${replayFile}.lock`),
        false,
      );
    } finally {
      cleanup(replayFile);
    }
  },
);

test(
  "durable replay fails closed when a stale lock exists",
  () => {
    const replayFile = temporaryPath("stale-replay.json");

    try {
      writeFileSync(
        replayFile,
        JSON.stringify([
          "P0.2-EXISTING-AUTH-001",
        ]),
        {
          encoding: "utf8",
          mode: 0o600,
        },
      );

      writeFileSync(`${replayFile}.lock`, "", {
        encoding: "utf8",
        mode: 0o600,
      });

      const store = new DurableExternalReplayStore(
        replayFile,
      );

      assert.equal(
        store.consume("P0.2-NEW-AUTH-001"),
        false,
      );

      assert.deepEqual(
        JSON.parse(readFileSync(replayFile, "utf8")),
        ["P0.2-EXISTING-AUTH-001"],
      );

      assert.equal(
        existsSync(`${replayFile}.lock`),
        true,
      );
    } finally {
      cleanup(replayFile);
    }
  },
);
