import { sha256 } from "./security.js";

function normalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(normalize);

  const record = value as Record<string, unknown>;
  return Object.keys(record).sort().reduce<Record<string, unknown>>(
    (out, key) => {
      out[key] = normalize(record[key]);
      return out;
    },
    {},
  );
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(normalize(value));
}

export function canonicalHash(value: unknown): string {
  return sha256(canonicalize(value));
}
