import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { canonicalize } from "../core/canonical.js";

export function signConstitutionalRule(
  rule: Omit<import("./types.js").ConstitutionalRule, "signature">,
  privateKeyPem: string,
): string {
  return sign(
    null,
    Buffer.from(canonicalize(rule)),
    createPrivateKey(privateKeyPem),
  ).toString("base64");
}

export function verifyConstitutionalRule(
  rule: import("./types.js").ConstitutionalRule,
  publicKeyPem: string,
): boolean {
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
