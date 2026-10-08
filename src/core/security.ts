import { createHash, timingSafeEqual } from "node:crypto";

export function sha256(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
