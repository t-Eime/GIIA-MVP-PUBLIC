import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { canonicalize } from "../core/canonical.js";

export interface GeneratedKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export function generateEd25519KeyPair(): GeneratedKeyPair {
  const pair = generateKeyPairSync("ed25519", {
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
  });

  return {
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
  };
}

export function signCanonical(
  payload: unknown,
  privateKeyPem: string,
): string {
  const key = createPrivateKey(privateKeyPem);
  return sign(null, Buffer.from(canonicalize(payload)), key).toString("base64");
}

export function verifyCanonical(
  payload: unknown,
  signature: string,
  publicKeyPem: string,
): boolean {
  try {
    const key = createPublicKey(publicKeyPem);

    return verify(
      null,
      Buffer.from(canonicalize(payload)),
      key,
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}
