import { runOnce } from "./runtime/runtime.js";
import { governObservation } from "./runtime/governed.js";

console.log("============================================");
console.log(" GIIA EXPERIMENTAL RUNTIME v0.3.0");
console.log("============================================");
console.log("MODE OBSERVATION + GOVERNED EVIDENCE");
console.log("AUTHORITY GIIA AUTHORITATIVE PIPELINE");
console.log("AI AUTONOMY NONE");
console.log();

const runtime = await runOnce();
const observation = runtime.observation;

if (!observation) {
  throw new Error("GIIA_RUNTIME_FAIL_CLOSED: OBSERVATION_MISSING");

console.log("===== OBSERVATION =====");
console.log("ID", observation.observationId);
console.log("DEVICE", observation.device.androidModel);
console.log("ANDROID", observation.device.androidVersion);
console.log("FILESYSTEM ROOTS", observation.filesystem.length);
console.log("NETWORK INTERFACES", Object.keys(observation.network).length);
console.log("OBSERVATION HASH", observation.contentHash);

console.log();
console.log("===== OBSERVER CHAIN =====");
console.log("CHAIN VALID", runtime.chain.valid);
console.log("CHAIN RECORDS", runtime.chain.records);
console.log("CHAIN HEAD", runtime.chain.head);

if (!runtime.chain.valid) {
  throw new Error("GIIA_RUNTIME_FAIL_CLOSED: OBSERVATION_CHAIN_INVALID");

console.log();
console.log("===== GIIA GOVERNANCE =====");

const executionIntent = {
  target: `observation:${observation.observationId}`,
  payload: {
    observationHash: observation.contentHash,
    chainHead: runtime.chain.head,
  },
};

const governed = governObservation(
  {
    id: observation.observationId,
    observedAt: observation.timestamp,
    observationHash: observation.contentHash,
    device: observation.device,
    filesystem: observation.filesystem,
    network: observation.network,
    processes: observation.processes,
  },
  executionIntent,
);

console.log("REQUEST", governed.requestId);
console.log("DECISION", governed.decision);
console.log("REASON", governed.reason);
console.log("AUTHORITATIVE", governed.authoritative);
console.log("TRUST VALID", governed.trustValid);
console.log("GOVERNANCE", governed.governanceDecision);
console.log("AUTHORIZATION", governed.authorizationDecision);
console.log("EVIDENCE", governed.evidence?.recordHash ?? "NONE");
console.log("AUDIT", governed.audit?.recordHash ?? "NONE");

if (!governed.trustValid) {
  throw new Error("GIIA_RUNTIME_FAIL_CLOSED: TRUST_INVALID");

if (governed.decision !== "ALLOW") {
  throw new Error(
    `GIIA_RUNTIME_FAIL_CLOSED: ${governed.reason}`,
  );

console.log();
console.log("===== ENFORCEMENT BOUNDARY =====");
console.log("EXECUTION", "EXTERNAL_EXECUTOR_REQUIRED");
console.log("GIIA EXECUTION AUTHORITY", "NONE");
console.log("GOVERNANCE ALLOW IS NOT EXECUTION");
console.log();
console.log("===== GOVERNED OBSERVATION ACCEPTED =====");
console.log("The observation passed the authoritative trust-to-action boundary.");
console.log("GIIA governance completed. Execution remains outside GIIA authority.");
console.log("============================================");
