import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const DATA = path.resolve("runtime-data");
const FILE = path.join(DATA, "observation-chain.jsonl");

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function lastRecord() {
  if (!fs.existsSync(FILE)) return null;

  const lines = fs.readFileSync(FILE, "utf8")
    .split("\n")
    .filter(Boolean);

  if (!lines.length) return null;

  try {
    return JSON.parse(lines[lines.length - 1]);
  } catch {
    return null;
  }
}

function appendObservation(observation) {
  fs.mkdirSync(DATA, { recursive: true });

  const previous = lastRecord();
  const previousHash = previous ? previous.recordHash : null;

  const record = {
    recordId: crypto.randomUUID(),
    previousHash,
    observation
  };

  record.recordHash = hash(JSON.stringify(record));

  fs.appendFileSync(
    FILE,
    JSON.stringify(record) + "\n",
    { mode: 0o600 }
  );

  return record;
}

function verifyChain() {
  if (!fs.existsSync(FILE)) {
    return { valid: true, records: 0 };
  }

  const lines = fs.readFileSync(FILE, "utf8")
    .split("\n")
    .filter(Boolean);

  let previous = null;

  for (let i = 0; i < lines.length; i++) {
    const record = JSON.parse(lines[i]);

    if (record.previousHash !== previous) {
      return {
        valid: false,
        records: lines.length,
        failure: "PREVIOUS_HASH_MISMATCH",
        index: i
      };
    }

    const copy = {
      recordId: record.recordId,
      previousHash: record.previousHash,
      observation: record.observation
    };

    const expected = hash(JSON.stringify(copy));

    if (record.recordHash !== expected) {
      return {
        valid: false,
        records: lines.length,
        failure: "RECORD_HASH_MISMATCH",
        index: i
      };
    }

    previous = record.recordHash;
  }

  return {
    valid: true,
    records: lines.length,
    head: previous
  };
}

export {
  appendObservation,
  verifyChain
};
