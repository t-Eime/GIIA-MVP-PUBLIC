import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { canonicalize } from "../core/canonical.js";
import type { GovernanceRule } from "./types.js";

export function signGovernanceRule(
  rule: Omit<GovernanceRule, "signature">,
  privateKeyPem: string,
): string {
  return sign(
    null,
    Buffer.from(canonicalize(rule)),
    createPrivateKey(privateKeyPem),
  ).toString("base64");
}

export function verifyGovernanceRule(
  rule: GovernanceRule,
  publicKeyPem: string,
): boolean {
  if (!rule.signature) return false;

  try {
    const { signature: _signature, ...payload } = rule;

    return verify(
      null,
      Buffer.from(canonicalize(payload)),
      createPublicKey(publicKeyPem),
      Buffer.from(rule.signature, "base64"),
    );
  } catch {
    return false;
  }
}
