import fs from "node:fs";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safe(fn, fallback = null) {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

function command(cmd, args = []) {
  return safe(() =>
    execFileSync(cmd, args, {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"]
    }).trim()
  );
}

function filesystemSnapshot() {
  const roots = [
    process.env.HOME,
    "/sdcard",
    "/storage/emulated/0"
  ].filter(Boolean);

  return roots.map(root => ({
    root,
    accessible: fs.existsSync(root),
    type: "filesystem-root"
  }));
}

function networkSnapshot() {
  const interfaces = os.networkInterfaces();
  const result = {};

  for (const [name, entries] of Object.entries(interfaces)) {
    result[name] = (entries || []).map(entry => ({
      family: entry.family,
      address: entry.address,
      internal: entry.internal
    }));
  }

  return result;
}

function processSnapshot() {
  return command("ps", ["-A"]) || command("ps") || "unavailable";
}

function deviceSnapshot() {
  return {
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    hostname: os.hostname(),
    release: os.release(),
    cpus: os.cpus().length,
    memoryBytes: os.totalmem(),
    freeMemoryBytes: os.freemem(),
    androidModel: command("getprop", ["ro.product.model"]),
    androidVersion: command("getprop", ["ro.build.version.release"]),
    sdk: command("getprop", ["ro.build.version.sdk"]),
    kernel: command("uname", ["-a"])
  };
}

function collectObservation() {
  const observation = {
    observationId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    source: "GIIA-EXPERIMENTAL-RUNTIME",
    device: deviceSnapshot(),
    filesystem: filesystemSnapshot(),
    network: networkSnapshot(),
    processes: processSnapshot()
  };

  observation.contentHash = sha256(JSON.stringify(observation));

  return observation;
}

export {
  collectObservation,
  sha256
};
