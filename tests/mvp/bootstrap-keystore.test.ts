import assert from "node:assert/strict";
import test from "node:test";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  readBootstrapKeystore,
  writeBootstrapKeystore,
  type BootstrapPrivateKeys,
} from "../../src/mvp/bootstrap-keystore.js";
import {
  governanceAuthoritySetFingerprint,
} from "../../src/security/governance-authority.js";

function makeAuthorityFixture() {
  const members = Array.from(
    { length: 5 },
    (_, index) => ({
      memberId: `governance-member-${index + 1}`,
      purpose: "governance" as const,
      status: "active" as const,
      publicKeyPem: `GOVERNANCE-PUBLIC-KEY-${index + 1}`,
    }),
  );

  const authoritySet = {
    setId: "giia-test-governance-authority-v1",
    version: 1,
    quorum: 3 as const,
    memberCount: 5 as const,
    members,
    fingerprint: governanceAuthoritySetFingerprint({
      setId: "giia-test-governance-authority-v1",
      version: 1,
      quorum: 3,
      memberCount: 5,
      members,
    }),
  };

  return {
    authoritySet,
    privateKeys: Object.fromEntries(
      members.map((member) => [
        member.memberId,
        `GOVERNANCE-PRIVATE-KEY-${member.memberId}`,
      ]),
    ),
  };
}

const authorityFixture = makeAuthorityFixture();

const KEYS: BootstrapPrivateKeys = {
  rootPrivateKeyPem: "ROOT-PRIVATE-KEY",
  anchorPrivateKeyPem: "ANCHOR-PRIVATE-KEY",
  delegationPrivateKeyPem: "DELEGATION-PRIVATE-KEY",
  governancePrivateKeyPem: "GOVERNANCE-PRIVATE-KEY",
  governanceAuthority: authorityFixture,
};

test("bootstrap keystore round-trips encrypted private keys", () => {
  const directory = mkdtempSync(
    join(tmpdir(), "giia-bootstrap-"),
  );
  const path = join(directory, "bootstrap.keys");

  try {
    writeBootstrapKeystore(
      path,
      "test-bootstrap-secret-123",
      KEYS,
    );

    assert.deepEqual(
      readBootstrapKeystore(
        path,
        "test-bootstrap-secret-123",
      ),
      KEYS,
    );

    const raw = readFileSync(path, "utf8");

    assert.equal(
      raw.includes("ROOT-PRIVATE-KEY"),
      false,
    );
    assert.equal(
      raw.includes("ANCHOR-PRIVATE-KEY"),
      false,
    );
  } finally {
    rmSync(directory, {
      recursive: true,
      force: true,
    });
  }
});

test("wrong bootstrap secret fails closed", () => {
  const directory = mkdtempSync(
    join(tmpdir(), "giia-bootstrap-"),
  );
  const path = join(directory, "bootstrap.keys");

  try {
    writeBootstrapKeystore(
      path,
      "correct-bootstrap-secret-123",
      KEYS,
    );

    assert.throws(
      () =>
        readBootstrapKeystore(
          path,
          "wrong-bootstrap-secret-123",
        ),
      /BOOTSTRAP_KEYSTORE_DECRYPTION_FAILED/,
    );
  } finally {
    rmSync(directory, {
      recursive: true,
      force: true,
    });
  }
});

test("keystore cannot be silently overwritten", () => {
  const directory = mkdtempSync(
    join(tmpdir(), "giia-bootstrap-"),
  );
  const path = join(directory, "bootstrap.keys");

  try {
    writeBootstrapKeystore(
      path,
      "bootstrap-secret-123",
      KEYS,
    );

    assert.throws(
      () =>
        writeBootstrapKeystore(
          path,
          "bootstrap-secret-123",
          KEYS,
        ),
    );
  } finally {
    rmSync(directory, {
      recursive: true,
      force: true,
    });
  }
});

test("missing keystore fails closed", () => {
  const directory = mkdtempSync(
    join(tmpdir(), "giia-bootstrap-"),
  );
  const path = join(directory, "missing.keys");

  try {
    assert.equal(existsSync(path), false);

    assert.throws(
      () =>
        readBootstrapKeystore(
          path,
          "bootstrap-secret-123",
        ),
      /BOOTSTRAP_KEYSTORE_MISSING/,
    );
  } finally {
    rmSync(directory, {
      recursive: true,
      force: true,
    });
  }
});

test("short bootstrap secret is rejected", () => {
  const directory = mkdtempSync(
    join(tmpdir(), "giia-bootstrap-"),
  );
  const path = join(directory, "bootstrap.keys");

  try {
    assert.throws(
      () =>
        writeBootstrapKeystore(
          path,
          "short",
          KEYS,
        ),
      /BOOTSTRAP_SECRET_TOO_SHORT/,
    );
  } finally {
    rmSync(directory, {
      recursive: true,
      force: true,
    });
  }
});
