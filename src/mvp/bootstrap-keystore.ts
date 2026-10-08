import {
  chmodSync,
  existsSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from "node:crypto";

const VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

import {
  GOVERNANCE_AUTHORITY_MEMBER_COUNT,
  GOVERNANCE_AUTHORITY_QUORUM,
  governanceAuthoritySetFingerprint,
  type GovernanceAuthoritySet,
} from "../security/governance-authority.js";

export interface BootstrapGovernanceAuthority {
  authoritySet: GovernanceAuthoritySet;
  privateKeys: Record<string, string>;
}

export interface BootstrapPrivateKeys {
  rootPrivateKeyPem: string;
  anchorPrivateKeyPem: string;
  delegationPrivateKeyPem: string;
  governancePrivateKeyPem: string;
  governanceAuthority: BootstrapGovernanceAuthority;
}

interface StoredKeystore {
  version: 1;
  algorithm: "aes-256-gcm";
  kdf: "scrypt";
  saltBase64: string;
  ivBase64: string;
  authTagBase64: string;
  ciphertextBase64: string;
}

function deriveKey(secret: string, salt: Buffer): Buffer {
  if (secret.length < 16) {
    throw new Error("BOOTSTRAP_SECRET_TOO_SHORT");
  }

  return scryptSync(secret, salt, KEY_LENGTH);
}

function encodeKeys(keys: BootstrapPrivateKeys): Buffer {
  return Buffer.from(JSON.stringify(keys), "utf8");
}

function decodeKeys(value: Buffer): BootstrapPrivateKeys {
  let parsed: unknown;

  try {
    parsed = JSON.parse(value.toString("utf8"));
  } catch {
    throw new Error("BOOTSTRAP_KEYSTORE_PAYLOAD_INVALID");
  }

  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed)
  ) {
    throw new Error("BOOTSTRAP_KEYSTORE_PAYLOAD_INVALID");
  }

  const object = parsed as Record<string, unknown>;

  const rootPrivateKeyPem = object.rootPrivateKeyPem;
  const anchorPrivateKeyPem = object.anchorPrivateKeyPem;
  const delegationPrivateKeyPem = object.delegationPrivateKeyPem;
  const governancePrivateKeyPem = object.governancePrivateKeyPem;
  const governanceAuthority = object.governanceAuthority;

  if (
    typeof rootPrivateKeyPem !== "string" ||
    typeof anchorPrivateKeyPem !== "string" ||
    typeof delegationPrivateKeyPem !== "string" ||
    typeof governancePrivateKeyPem !== "string"
  ) {
    throw new Error("BOOTSTRAP_PRIVATE_KEY_INVALID");
  }

  if (
    !governanceAuthority ||
    typeof governanceAuthority !== "object" ||
    Array.isArray(governanceAuthority)
  ) {
    throw new Error(
      "BOOTSTRAP_GOVERNANCE_AUTHORITY_INVALID",
    );
  }

  const authority =
    governanceAuthority as Record<string, unknown>;

  const authoritySet = authority.authoritySet;
  const privateKeys = authority.privateKeys;

  if (
    !authoritySet ||
    typeof authoritySet !== "object" ||
    Array.isArray(authoritySet) ||
    !privateKeys ||
    typeof privateKeys !== "object" ||
    Array.isArray(privateKeys)
  ) {
    throw new Error(
      "BOOTSTRAP_GOVERNANCE_AUTHORITY_INVALID",
    );
  }

  const set =
    authoritySet as Record<string, unknown>;

  if (
    typeof set.setId !== "string" ||
    typeof set.version !== "number" ||
    set.quorum !== GOVERNANCE_AUTHORITY_QUORUM ||
    set.memberCount !== GOVERNANCE_AUTHORITY_MEMBER_COUNT ||
    !Array.isArray(set.members) ||
    set.members.length !== GOVERNANCE_AUTHORITY_MEMBER_COUNT ||
    typeof set.fingerprint !== "string"
  ) {
    throw new Error(
      "BOOTSTRAP_GOVERNANCE_AUTHORITY_INVALID",
    );
  }

  const memberIds = new Set<string>();

  for (const member of set.members) {
    if (
      !member ||
      typeof member !== "object" ||
      Array.isArray(member)
    ) {
      throw new Error(
        "BOOTSTRAP_GOVERNANCE_AUTHORITY_INVALID",
      );
    }

    const row = member as Record<string, unknown>;

    if (
      typeof row.memberId !== "string" ||
      row.purpose !== "governance" ||
      row.status !== "active" ||
      typeof row.publicKeyPem !== "string" ||
      row.publicKeyPem.length === 0 ||
      memberIds.has(row.memberId)
    ) {
      throw new Error(
        "BOOTSTRAP_GOVERNANCE_AUTHORITY_INVALID",
      );
    }

    memberIds.add(row.memberId);
  }

  const fingerprintInput = {
    setId: set.setId,
    version: set.version,
    quorum: set.quorum,
    memberCount: set.memberCount,
    members: set.members,
  };

  const expectedFingerprint =
    governanceAuthoritySetFingerprint(
      fingerprintInput as Omit<
        GovernanceAuthoritySet,
        "fingerprint"
      >,
    );

  if (expectedFingerprint !== set.fingerprint) {
    throw new Error(
      "BOOTSTRAP_GOVERNANCE_AUTHORITY_FINGERPRINT_INVALID",
    );
  }

  const privateKeyMap =
    privateKeys as Record<string, unknown>;

  const privateIds = Object.keys(privateKeyMap);

  if (
    privateIds.length !==
    GOVERNANCE_AUTHORITY_MEMBER_COUNT
  ) {
    throw new Error(
      "BOOTSTRAP_GOVERNANCE_AUTHORITY_PRIVATE_KEY_COUNT_INVALID",
    );
  }

  for (const memberId of privateIds) {
    if (
      !memberIds.has(memberId) ||
      typeof privateKeyMap[memberId] !== "string" ||
      privateKeyMap[memberId].length === 0
    ) {
      throw new Error(
        "BOOTSTRAP_GOVERNANCE_AUTHORITY_PRIVATE_KEY_INVALID",
      );
    }
  }

  return {
    rootPrivateKeyPem,
    anchorPrivateKeyPem,
    delegationPrivateKeyPem,
    governancePrivateKeyPem,
    governanceAuthority: {
      authoritySet: set as unknown as GovernanceAuthoritySet,
      privateKeys: Object.fromEntries(
        privateIds.map((memberId) => [
          memberId,
          String(privateKeyMap[memberId]),
        ]),
      ),
    },
  };
}

export function writeBootstrapKeystore(
  path: string,
  secret: string,
  keys: BootstrapPrivateKeys,
): void {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const encryptionKey = deriveKey(secret, salt);

  const cipher = createCipheriv(
    ALGORITHM,
    encryptionKey,
    iv,
  );

  const ciphertext = Buffer.concat([
    cipher.update(encodeKeys(keys)),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  const stored: StoredKeystore = {
    version: VERSION,
    algorithm: ALGORITHM,
    kdf: "scrypt",
    saltBase64: salt.toString("base64"),
    ivBase64: iv.toString("base64"),
    authTagBase64: authTag.toString("base64"),
    ciphertextBase64: ciphertext.toString("base64"),
  };

  writeFileSync(
    path,
    JSON.stringify(stored, null, 2),
    {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    },
  );

  try {
    chmodSync(path, 0o600);
  } catch {
    // Windows and some restricted filesystems may not support chmod.
  }
}

export function readBootstrapKeystore(
  path: string,
  secret: string,
): BootstrapPrivateKeys {
  if (!existsSync(path)) {
    throw new Error("BOOTSTRAP_KEYSTORE_MISSING");
  }

  let stored: StoredKeystore;

  try {
    stored = JSON.parse(
      readFileSync(path, "utf8"),
    ) as StoredKeystore;

    if (
      !stored ||
      typeof stored !== "object" ||
      Array.isArray(stored) ||
      stored.version !== VERSION ||
      stored.algorithm !== ALGORITHM ||
      stored.kdf !== "scrypt"
    ) {
      throw new Error("BOOTSTRAP_KEYSTORE_FORMAT_INVALID");
    }
  } catch {
    throw new Error("BOOTSTRAP_KEYSTORE_DECRYPTION_FAILED");
  }

  try {
    const salt = Buffer.from(stored.saltBase64, "base64");
    const iv = Buffer.from(stored.ivBase64, "base64");
    const authTag = Buffer.from(
      stored.authTagBase64,
      "base64",
    );
    const ciphertext = Buffer.from(
      stored.ciphertextBase64,
      "base64",
    );

    if (
      salt.length !== SALT_LENGTH ||
      iv.length !== IV_LENGTH ||
      authTag.length !== 16 ||
      ciphertext.length === 0
    ) {
      throw new Error("BOOTSTRAP_KEYSTORE_ENCODING_INVALID");
    }

    const encryptionKey = deriveKey(secret, salt);

    const decipher = createDecipheriv(
      ALGORITHM,
      encryptionKey,
      iv,
    );

    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return decodeKeys(plaintext);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === "BOOTSTRAP_SECRET_TOO_SHORT"
    ) {
      throw error;
    }

    throw new Error("BOOTSTRAP_KEYSTORE_DECRYPTION_FAILED");
  }
}
