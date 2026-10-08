import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createMvpComposition } from "../../src/mvp/composition.js";

function tempPaths() {
  const dir = mkdtempSync(join(tmpdir(), "giia-durable-"));
  return {
    dir,
    keystorePath: join(dir, "bootstrap.keystore"),
    trustRegistryPath: join(dir, "trust.db"),
  };
}

function request(id: string) {
  return {
    requestId: id,
    action: "read",
    resource: "resource-001",
    requestedAt: "2026-01-01T00:00:00.000Z",
  };
}

function createDurable(paths: ReturnType<typeof tempPaths>) {
  process.env.GIIA_MVP_KEYSTORE_SECRET =
    "test-durable-bootstrap-secret-2026";

  return createMvpComposition({
    durableBootstrap: true,
    bootstrapPaths: {
      keystorePath: paths.keystorePath,
      trustRegistryPath: paths.trustRegistryPath,
    },
  });
}

test("MVP-DURABLE-001 durable bootstrap creates keystore and trust registry", () => {
  const paths = tempPaths();

  const composition = createDurable(paths);
  composition.close();

  assert.ok(readFileSync(paths.keystorePath));
  assert.ok(readFileSync(paths.trustRegistryPath));
});

test("MVP-DURABLE-002 durable restart preserves the exact governance signing key", () => {
  const paths = tempPaths();

  const first = createDurable(paths);
  const firstResult = first.evaluate(request("restart-key-1"));
  console.log("RESTART FIRST RESULT", firstResult);

  assert.equal(firstResult.decision, "ALLOW");

  const firstRecord = first.createDecisionRecord(
    firstResult,
    "restart-key-1",
    "read",
    "resource-001",
    "2026-01-01T00:00:01.000Z",
  );

  const firstSigner = firstRecord.signerKeyId;
  const firstPublicKey = firstRecord.signerPublicKeyPem;
  first.close();

  const second = createDurable(paths);
  const secondResult = second.evaluate(request("restart-key-2"));
  console.log("RESTART SECOND RESULT", secondResult);

  assert.equal(secondResult.decision, "ALLOW");

  const secondRecord = second.createDecisionRecord(
    secondResult,
    "restart-key-2",
    "read",
    "resource-001",
    "2026-01-01T00:00:02.000Z",
  );

  assert.equal(secondRecord.signerKeyId, firstSigner);
  assert.equal(secondRecord.signerPublicKeyPem, firstPublicKey);

  second.close();
});

test("MVP-DURABLE-003 wrong durable bootstrap secret fails closed", () => {
  const paths = tempPaths();

  process.env.GIIA_MVP_KEYSTORE_SECRET =
    "correct-durable-bootstrap-secret";

  const first = createMvpComposition({
    durableBootstrap: true,
    bootstrapPaths: paths,
  });
  first.close();

  process.env.GIIA_MVP_KEYSTORE_SECRET =
    "wrong-durable-bootstrap-secret";

  assert.throws(
    () =>
      createMvpComposition({
        durableBootstrap: true,
        bootstrapPaths: paths,
      }),
    /BOOTSTRAP_KEYSTORE_DECRYPTION_FAILED/,
  );
});

test("MVP-DURABLE-004 partial durable bootstrap state fails closed", () => {
  const paths = tempPaths();

  process.env.GIIA_MVP_KEYSTORE_SECRET =
    "partial-state-bootstrap-secret";

  writeFileSync(paths.keystorePath, "partial");

  assert.throws(
    () =>
      createMvpComposition({
        durableBootstrap: true,
        bootstrapPaths: paths,
      }),
    /DURABLE_BOOTSTRAP_PARTIAL_STATE/,
  );
});

test("MVP-DURABLE-005 keystore private/public substitution fails closed", () => {
  const paths = tempPaths();

  process.env.GIIA_MVP_KEYSTORE_SECRET =
    "substitution-bootstrap-secret";

  const first = createMvpComposition({
    durableBootstrap: true,
    bootstrapPaths: paths,
  });
  first.close();

  const original = readFileSync(paths.keystorePath);

  // Corrupt the encrypted keystore without changing its path.
  const corrupted = Buffer.from(original);
  const lastIndex = corrupted.length - 1;

  assert.ok(lastIndex >= 0);

  const originalByte = corrupted.readUInt8(lastIndex);
  corrupted.writeUInt8(originalByte ^ 0xff, lastIndex);

  writeFileSync(paths.keystorePath, corrupted);

  assert.throws(
    () =>
      createMvpComposition({
        durableBootstrap: true,
        bootstrapPaths: paths,
      }),
    /BOOTSTRAP_KEYSTORE_DECRYPTION_FAILED/,
  );
});

test("MVP-DURABLE-006 persisted trust-state substitution fails closed", () => {
  const paths = tempPaths();

  process.env.GIIA_MVP_KEYSTORE_SECRET =
    "trust-state-substitution-secret";

  const first = createMvpComposition({
    durableBootstrap: true,
    bootstrapPaths: paths,
  });
  first.close();

  /*
   * Open the SQLite file directly and mutate a persisted public key.
   * The durable loader must reject it because the persisted trust state
   * no longer matches the encrypted bootstrap identity.
   */
  const db = new DatabaseSync(paths.trustRegistryPath);

  const row = db
    .prepare(
      "SELECT payload FROM trust_keys WHERE id = 'mvp-governance-key'",
    )
    .get() as { payload?: unknown } | undefined;

  assert.ok(row);
  assert.equal(typeof row.payload, "string");

  const payload = JSON.parse(String(row.payload)) as Record<string, unknown>;

  assert.equal(typeof payload.publicKeyPem, "string");

  payload.publicKeyPem = String(payload.publicKeyPem).replace(
    /BEGIN PUBLIC KEY/,
    "BEGIN PUBLIC KEY\\nCORRUPTED",
  );

  db.prepare(
    "UPDATE trust_keys SET payload = ? WHERE id = 'mvp-governance-key'",
  ).run(JSON.stringify(payload));

  db.close();

  assert.throws(
    () =>
      createMvpComposition({
        durableBootstrap: true,
        bootstrapPaths: paths,
      }),
    /BOOTSTRAP_PRIVATE_PUBLIC_KEY_MISMATCH/,
  );
});
