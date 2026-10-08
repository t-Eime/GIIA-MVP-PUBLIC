import { invariant } from "./errors.js";

export function validateNonEmpty(value: string, code: string, message: string): void {
  invariant(value.trim().length > 0, code, message);
}

export function validateTimestamp(value: string, code: string, message: string): void {
  invariant(
    Number.isFinite(Date.parse(value)),
    code,
    message,
  );
}

export function validateSha256(value: string, code: string, message: string): void {
  invariant(
    /^[a-f0-9]{64}$/i.test(value),
    code,
    message,
  );
}
