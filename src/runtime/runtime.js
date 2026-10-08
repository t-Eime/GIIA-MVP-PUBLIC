import fs from "node:fs";
import path from "node:path";
import { collectObservation } from "./observer.js";
import { appendObservation, verifyChain } from "./evidence.js";

const RUNTIME_DIR = path.resolve("runtime-data");
const STATE = path.join(RUNTIME_DIR, "runtime-state.json");

function loadState() {
  if (!fs.existsSync(STATE)) {
    return {
      runtime: "GIIA-EXPERIMENTAL-RUNTIME",
      version: "0.1.0",
      started: new Date().toISOString(),
      observations: 0
    };
  }

  return JSON.parse(fs.readFileSync(STATE, "utf8"));
}

function saveState(state) {
  fs.mkdirSync(RUNTIME_DIR, { recursive: true });

  fs.writeFileSync(
    STATE,
    JSON.stringify(state, null, 2),
    { mode: 0o600 }
  );
}

function runOnce() {
  const state = loadState();
  const observation = collectObservation();
  const record = appendObservation(observation);

  state.observations++;
  state.lastObservation = observation.timestamp;
  state.lastRecordHash = record.recordHash;

  saveState(state);

  return {
    state,
    observation,
    evidence: {
      recordId: record.recordId,
      recordHash: record.recordHash,
      previousHash: record.previousHash
    },
    chain: verifyChain()
  };
}

export {
  runOnce
};
