import { existsSync } from "node:fs";

import {
  createPrivateKey,
  createPublicKey,
} from "node:crypto";

import {
  readBootstrapKeystore,
  writeBootstrapKeystore,
  type BootstrapPrivateKeys,
} from "./bootstrap-keystore.js";

import {
  createTrustKey,
} from "../trust/service.js";

import {
  generateGovernanceAuthorityMember,
  createGovernanceAuthoritySet,
  type GovernanceAuthorityKeyPair,
  type GovernanceAuthoritySet,
} from "../security/governance-authority.js";

import type { TrustKey } from "../trust/types.js";

import { KeySecurityBoundary } from "../security/key-boundary.js";

export interface DurableBootstrapPaths {
  keystorePath: string;
  trustRegistryPath: string;
}

export interface DurableBootstrapState {
  keys: {
    root: TrustKey;
    anchor: TrustKey;
    delegation: TrustKey;
    governance: TrustKey;
  };
  governanceAuthority: {
    authoritySet: GovernanceAuthoritySet;
    members: readonly GovernanceAuthorityKeyPair[];
  };
  privateKeys: BootstrapPrivateKeys;
}

function publicKeyPemFromPrivate(privateKeyPem: string): string {
  return createPublicKey(
    createPrivateKey(privateKeyPem),
  )
    .export({
      format: "pem",
      type: "spki",
    })
    .toString();
}

function assertPrivateMatchesPublic(
  privateKeyPem: string,
  expectedPublicKeyPem: string,
): void {
  const actual = publicKeyPemFromPrivate(privateKeyPem);

  if (actual !== expectedPublicKeyPem) {
    throw new Error("BOOTSTRAP_PRIVATE_PUBLIC_KEY_MISMATCH");
  }
}

function requireSecret(): string {
  const secret = process.env.GIIA_MVP_KEYSTORE_SECRET;

  if (
    typeof secret !== "string" ||
    secret.length < 16
  ) {
    throw new Error("GIIA_MVP_KEYSTORE_SECRET_REQUIRED");
  }

  return secret;
}

function createBootstrapKey(
  id: string,
  purpose: TrustKey["purpose"],
  provenance: string,
  createdAt: string,
) {
  return createTrustKey(
    id,
    purpose,
    provenance,
    createdAt,
  );
}

export function initializeDurableBootstrap(
  paths: DurableBootstrapPaths,
  createdAt: string,
): DurableBootstrapState {
  if (
    existsSync(paths.keystorePath) ||
    existsSync(paths.trustRegistryPath)
  ) {
    throw new Error(
      "DURABLE_BOOTSTRAP_ALREADY_EXISTS",
    );
  }

  const secret = requireSecret();

  const root = createBootstrapKey(
    "mvp-root-key",
    "root",
    "giia-mvp-durable-bootstrap",
    createdAt,
  );

  const anchor = createBootstrapKey(
    "mvp-anchor-key",
    "anchor",
    "giia-mvp-durable-bootstrap",
    createdAt,
  );

  const delegation = createBootstrapKey(
    "mvp-delegation-key",
    "delegation",
    "giia-mvp-durable-bootstrap",
    createdAt,
  );

  const governance = createBootstrapKey(
    "mvp-governance-key",
    "governance",
    "giia-mvp-durable-bootstrap",
    createdAt,
  );

  const governanceMembers: GovernanceAuthorityKeyPair[] =
    Array.from(
      { length: 5 },
      (_, index) =>
        generateGovernanceAuthorityMember(
          `governance-member-${index + 1}`,
        ),
    );

  const authoritySet = createGovernanceAuthoritySet(
    "giia-governance-authority-v1",
    1,
    governanceMembers.map(
      (member) => member.member,
    ),
  );

  const privateKeys: BootstrapPrivateKeys = {
    rootPrivateKeyPem: root.privateKeyPem,
    anchorPrivateKeyPem: anchor.privateKeyPem,
    delegationPrivateKeyPem: delegation.privateKeyPem,
    governancePrivateKeyPem: governance.privateKeyPem,
    governanceAuthority: {
      authoritySet,
      privateKeys: Object.fromEntries(
        governanceMembers.map(
          (member) => [
            member.member.memberId,
            member.privateKeyPem,
          ],
        ),
      ),
    },
  };

  writeBootstrapKeystore(
    paths.keystorePath,
    secret,
    privateKeys,
  );

  return {
    keys: {
      root: root.key,
      anchor: anchor.key,
      delegation: delegation.key,
      governance: governance.key,
    },
    governanceAuthority: {
      authoritySet,
      members: governanceMembers,
    },
    privateKeys,
  };
}

export function loadDurableBootstrap(
  paths: DurableBootstrapPaths,
  expectedKeys: DurableBootstrapState["keys"],
): DurableBootstrapState {
  if (!existsSync(paths.keystorePath)) {
    throw new Error("BOOTSTRAP_KEYSTORE_MISSING");
  }

  const secret = requireSecret();

  const privateKeys = readBootstrapKeystore(
    paths.keystorePath,
    secret,
  );

  assertPrivateMatchesPublic(
    privateKeys.rootPrivateKeyPem,
    expectedKeys.root.publicKeyPem,
  );

  assertPrivateMatchesPublic(
    privateKeys.anchorPrivateKeyPem,
    expectedKeys.anchor.publicKeyPem,
  );

  assertPrivateMatchesPublic(
    privateKeys.delegationPrivateKeyPem,
    expectedKeys.delegation.publicKeyPem,
  );

  assertPrivateMatchesPublic(
    privateKeys.governancePrivateKeyPem,
    expectedKeys.governance.publicKeyPem,
  );

  const authoritySet =
    privateKeys.governanceAuthority.authoritySet;

  if (
    authoritySet.quorum !== 3 ||
    authoritySet.memberCount !== 5 ||
    authoritySet.members.length !== 5
  ) {
    throw new Error(
      "BOOTSTRAP_GOVERNANCE_AUTHORITY_INVALID",
    );
  }

  const authorityMembers: GovernanceAuthorityKeyPair[] =
    authoritySet.members.map((member) => {
      const privateKeyPem =
        privateKeys.governanceAuthority.privateKeys[
          member.memberId
        ];

      if (typeof privateKeyPem !== "string") {
        throw new Error(
          "BOOTSTRAP_GOVERNANCE_AUTHORITY_PRIVATE_KEY_MISSING",
        );
      }

      assertPrivateMatchesPublic(
        privateKeyPem,
        member.publicKeyPem,
      );

      return {
        member,
        privateKeyPem,
      };
    });

  if (authorityMembers.length !== 5) {
    throw new Error(
      "BOOTSTRAP_GOVERNANCE_AUTHORITY_INVALID",
    );
  }

  return {
    keys: expectedKeys,
    governanceAuthority: {
      authoritySet,
      members: authorityMembers,
    },
    privateKeys,
  };
}

export function registerBootstrapKeys(
  state: DurableBootstrapState,
  boundary: KeySecurityBoundary,
  at: string,
): void {
  boundary.register(
    state.keys.root,
    state.privateKeys.rootPrivateKeyPem,
    at,
  );

  boundary.register(
    state.keys.anchor,
    state.privateKeys.anchorPrivateKeyPem,
    at,
  );

  boundary.register(
    state.keys.delegation,
    state.privateKeys.delegationPrivateKeyPem,
    at,
  );

  boundary.register(
    state.keys.governance,
    state.privateKeys.governancePrivateKeyPem,
    at,
  );
}
