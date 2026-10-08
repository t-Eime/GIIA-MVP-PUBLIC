import {
  createAnchorWithSecureKey,
  createCredentialWithSecureKey,
  createDelegationWithSecureKey,
  createRoot,
  createTrustKey,
  verifyTrustChain,
  type TrustChainInput,
} from "../trust/service.js";
import { KeySecurityBoundary } from "../security/key-boundary.js";
import { TrustRegistry } from "../trust/registry.js";
import { EvidenceAuditRegistry } from "../evidence-audit/registry.js";
import { signConstitutionalRule } from "../constitution/crypto.js";
import { signGovernanceRule } from "../governance/crypto.js";
import { createEvidenceHash } from "../evidence/service.js";
import { createAuditHash } from "../audit/service.js";
import { evaluateTrustToAction } from "../trust-action/service.js";
import {
  createGovernanceSigningKey,
} from "../governance-decision/crypto.js";
import {
  createGovernanceKeyAuthorization,
  type SignedGovernanceKeyAuthorization,
} from "../governance-decision/authorization.js";
import {
  initializeDurableBootstrap,
  loadDurableBootstrap,
  type DurableBootstrapState,
} from "./bootstrap-trust.js";
import { existsSync } from "node:fs";
import { createDecisionRecord } from "./decision-record.js";
import type { MvpDecisionRecord } from "./types.js";
import {
  generateGovernanceAuthorityMember,
  createGovernanceAuthoritySet,
  type GovernanceAuthorityKeyPair,
  type GovernanceAuthoritySet,
} from "../security/governance-authority.js";

import type { Identity } from "../identity/types.js";
import type { Authority } from "../authority/types.js";
import type { AuthorizationRequest } from "../authorization/types.js";
import type { GovernanceRule } from "../governance/types.js";
import type { ConstitutionalRule } from "../constitution/types.js";
import type { Evidence } from "../evidence/types.js";
import type { AuditEvent } from "../audit/types.js";
import type { ActionIntent } from "../trust-action/types.js";
import type { TrustToActionResult } from "../trust-action/types.js";

const BOOTSTRAP_AT = "2026-01-01T00:00:00.000Z";

export interface MvpCompositionOptions {
  trustRegistryPath?: string;
  evidenceAuditRegistryPath?: string;
  durableBootstrap?: boolean;
  bootstrapPaths?: {
    keystorePath: string;
    trustRegistryPath: string;
  };
}

export interface MvpComposition {
  evaluate(input: {
    requestId: string;
    action: string;
    resource: string;
    requestedAt: string;
  }): TrustToActionResult;

  createDecisionRecord(
    result: TrustToActionResult,
    requestId: string,
    action: string,
    resource: string,
    issuedAt: string,
  ): MvpDecisionRecord;

  close(): void;
}

function identity(): Identity {
  return {
    id: "mvp-identity-001",
    kind: "human",
    status: "active",
    provenance: "giia-mvp-bootstrap",
    createdAt: BOOTSTRAP_AT,
  };
}

function authority(identityId: string): Authority {
  return {
    id: "mvp-authority-001",
    holderIdentityId: identityId,
    trustCredentialId: "mvp-credential",
    scope: ["read:resource-001"],
    issuedAt: BOOTSTRAP_AT,
    status: "active",
    issuer: "mvp-bootstrap",
    provenance: "giia-mvp-bootstrap",
  };
}

function createEphemeralChain(
  subjectId: string,
  authorityId: string,
): {
  trustChain: TrustChainInput;
  delegationPrivateKeyPem: string;
  governanceKey: ReturnType<typeof createTrustKey>["key"];
  governancePrivateKeyPem: string;
  boundary: KeySecurityBoundary;
  governanceAuthoritySet: GovernanceAuthoritySet;
  governanceAuthorityMembers: readonly GovernanceAuthorityKeyPair[];
} {
  const rootGenerated = createTrustKey(
    "mvp-root-key",
    "root",
    "giia-mvp-bootstrap",
    BOOTSTRAP_AT,
  );

  const anchorGenerated = createTrustKey(
    "mvp-anchor-key",
    "anchor",
    "giia-mvp-bootstrap",
    BOOTSTRAP_AT,
  );

  const delegationGenerated = createTrustKey(
    "mvp-delegation-key",
    "delegation",
    "giia-mvp-bootstrap",
    BOOTSTRAP_AT,
  );

  const governanceGenerated = createGovernanceSigningKey(
    "mvp-governance-key",
    "giia-mvp-bootstrap",
    BOOTSTRAP_AT,
  );

  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();
  const governanceBoundary = new KeySecurityBoundary();

  rootBoundary.register(
    rootGenerated.key,
    rootGenerated.privateKeyPem,
    BOOTSTRAP_AT,
  );

  anchorBoundary.register(
    anchorGenerated.key,
    anchorGenerated.privateKeyPem,
    BOOTSTRAP_AT,
  );

  delegationBoundary.register(
    delegationGenerated.key,
    delegationGenerated.privateKeyPem,
    BOOTSTRAP_AT,
  );

  governanceBoundary.register(
    governanceGenerated.key,
    governanceGenerated.privateKeyPem,
    BOOTSTRAP_AT,
  );

  const root = createRoot(
    "mvp-root",
    "mvp-root-subject",
    rootGenerated.key.id,
    BOOTSTRAP_AT,
    "giia-mvp-bootstrap",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: "mvp-anchor",
      subject: "mvp-anchor-subject",
      rootId: root.id,
      signingKeyId: rootGenerated.key.id,
      constraints: ["issue:credential"],
      issuedAt: BOOTSTRAP_AT,
      status: "active",
      provenance: "giia-mvp-bootstrap",
    },
    {
      boundary: rootBoundary,
      keyId: rootGenerated.key.id,
      purpose: "root",
      at: BOOTSTRAP_AT,
    },
  );

  const delegation = createDelegationWithSecureKey(
    {
      id: "mvp-delegation",
      issuerAnchorId: anchor.id,
      delegateeId: subjectId,
      signingKeyId: anchorGenerated.key.id,
      constraints: ["credential:issue"],
      issuedAt: BOOTSTRAP_AT,
      status: "active",
      provenance: "giia-mvp-bootstrap",
    },
    {
      boundary: anchorBoundary,
      keyId: anchorGenerated.key.id,
      purpose: "anchor",
      at: BOOTSTRAP_AT,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: "mvp-credential",
      subject: subjectId,
      issuerDelegationId: delegation.id,
      claims: {
        authorityId,
        "governance:constitutional": "true",
        "governance:policy": "true",
      },
      issuedAt: BOOTSTRAP_AT,
      status: "active",
      provenance: "giia-mvp-bootstrap",
    },
    {
      boundary: delegationBoundary,
      keyId: delegationGenerated.key.id,
      purpose: "delegation",
      at: BOOTSTRAP_AT,
    },
  );

  const governanceAuthorityMembers =
    Array.from(
      { length: 5 },
      (_, index) =>
        generateGovernanceAuthorityMember(
          `governance-member-${index + 1}`,
        ),
    );

  const governanceAuthoritySet =
    createGovernanceAuthoritySet(
      "giia-governance-authority-ephemeral-v1",
      1,
      governanceAuthorityMembers.map(
        (member) => member.member,
      ),
    );

  return {
    trustChain: {
      root,
      rootKey: rootGenerated.key,
      anchor,
      anchorKey: anchorGenerated.key,
      delegation,
      delegationKey: delegationGenerated.key,
      credential,
      at: BOOTSTRAP_AT,
    },
    delegationPrivateKeyPem:
      delegationGenerated.privateKeyPem,
    governanceKey: governanceGenerated.key,
    governancePrivateKeyPem:
      governanceGenerated.privateKeyPem,
    boundary: governanceBoundary,
    governanceAuthoritySet,
    governanceAuthorityMembers,
  };
}

function createDurableChain(
  subjectId: string,
  authorityId: string,
  state: DurableBootstrapState,
): {
  trustChain: TrustChainInput;
  delegationPrivateKeyPem: string;
  governanceKey: DurableBootstrapState["keys"]["governance"];
  governancePrivateKeyPem: string;
  boundary: KeySecurityBoundary;
  governanceAuthoritySet: GovernanceAuthoritySet;
  governanceAuthorityMembers: readonly GovernanceAuthorityKeyPair[];
} {
  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();
  const governanceBoundary = new KeySecurityBoundary();

  rootBoundary.register(
    state.keys.root,
    state.privateKeys.rootPrivateKeyPem,
    BOOTSTRAP_AT,
  );

  anchorBoundary.register(
    state.keys.anchor,
    state.privateKeys.anchorPrivateKeyPem,
    BOOTSTRAP_AT,
  );

  delegationBoundary.register(
    state.keys.delegation,
    state.privateKeys.delegationPrivateKeyPem,
    BOOTSTRAP_AT,
  );

  governanceBoundary.register(
    state.keys.governance,
    state.privateKeys.governancePrivateKeyPem,
    BOOTSTRAP_AT,
  );

  const root = createRoot(
    "mvp-root",
    "mvp-root-subject",
    state.keys.root.id,
    BOOTSTRAP_AT,
    "giia-mvp-durable-bootstrap",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: "mvp-anchor",
      subject: "mvp-anchor-subject",
      rootId: root.id,
      signingKeyId: state.keys.root.id,
      constraints: ["issue:credential"],
      issuedAt: BOOTSTRAP_AT,
      status: "active",
      provenance: "giia-mvp-durable-bootstrap",
    },
    {
      boundary: rootBoundary,
      keyId: state.keys.root.id,
      purpose: "root",
      at: BOOTSTRAP_AT,
    },
  );

  const delegation = createDelegationWithSecureKey(
    {
      id: "mvp-delegation",
      issuerAnchorId: anchor.id,
      delegateeId: subjectId,
      signingKeyId: state.keys.anchor.id,
      constraints: ["credential:issue"],
      issuedAt: BOOTSTRAP_AT,
      status: "active",
      provenance: "giia-mvp-durable-bootstrap",
    },
    {
      boundary: anchorBoundary,
      keyId: state.keys.anchor.id,
      purpose: "anchor",
      at: BOOTSTRAP_AT,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: "mvp-credential",
      subject: subjectId,
      issuerDelegationId: delegation.id,
      claims: {
        authorityId,
        "governance:constitutional": "true",
        "governance:policy": "true",
      },
      issuedAt: BOOTSTRAP_AT,
      status: "active",
      provenance: "giia-mvp-durable-bootstrap",
    },
    {
      boundary: delegationBoundary,
      keyId: state.keys.delegation.id,
      purpose: "delegation",
      at: BOOTSTRAP_AT,
    },
  );

  const trustChain: TrustChainInput = {
    root,
    rootKey: state.keys.root,
    anchor,
    anchorKey: state.keys.anchor,
    delegation,
    delegationKey: state.keys.delegation,
    credential,
    at: BOOTSTRAP_AT,
  };

  const verification = verifyTrustChain(trustChain);

  if (!verification.valid) {
    throw new Error(
      `DURABLE_BOOTSTRAP_TRUST_CHAIN_INVALID:${verification.reason}`,
    );
  }

  return {
    trustChain,
    delegationPrivateKeyPem:
      state.privateKeys.delegationPrivateKeyPem,
    governanceKey: state.keys.governance,
    governancePrivateKeyPem:
      state.privateKeys.governancePrivateKeyPem,
    boundary: governanceBoundary,
    governanceAuthoritySet:
      state.governanceAuthority.authoritySet,
    governanceAuthorityMembers:
      state.governanceAuthority.members,
  };
}

function loadPersistedDurableChain(
  registry: TrustRegistry,
  state: DurableBootstrapState,
): TrustChainInput {
  const root = registry.getRoot("mvp-root");
  const anchor = registry.getAnchor("mvp-anchor");
  const delegation = registry.getDelegation("mvp-delegation");
  const credential = registry.getCredential("mvp-credential");

  const rootKey = registry.getKey("mvp-root-key");
  const anchorKey = registry.getKey("mvp-anchor-key");
  const delegationKey = registry.getKey("mvp-delegation-key");
  const governanceKey = registry.getKey("mvp-governance-key");

  if (
    !root ||
    !anchor ||
    !delegation ||
    !credential ||
    !rootKey ||
    !anchorKey ||
    !delegationKey ||
    !governanceKey
  ) {
    throw new Error("DURABLE_TRUST_STATE_INCOMPLETE");
  }

  if (
    rootKey.id !== state.keys.root.id ||
    anchorKey.id !== state.keys.anchor.id ||
    delegationKey.id !== state.keys.delegation.id ||
    governanceKey.id !== state.keys.governance.id
  ) {
    throw new Error("DURABLE_TRUST_STATE_KEY_ID_MISMATCH");
  }

  if (
    rootKey.publicKeyPem !== state.keys.root.publicKeyPem ||
    anchorKey.publicKeyPem !== state.keys.anchor.publicKeyPem ||
    delegationKey.publicKeyPem !== state.keys.delegation.publicKeyPem ||
    governanceKey.publicKeyPem !== state.keys.governance.publicKeyPem
  ) {
    throw new Error("DURABLE_TRUST_STATE_KEY_MISMATCH");
  }

  const chain: TrustChainInput = {
    root,
    rootKey,
    anchor,
    anchorKey,
    delegation,
    delegationKey,
    credential,
    at: BOOTSTRAP_AT,
  };

  const verification = verifyTrustChain(chain);

  if (!verification.valid) {
    throw new Error(
      `DURABLE_BOOTSTRAP_TRUST_CHAIN_INVALID:${verification.reason}`,
    );
  }

  return chain;
}



function governanceRule(privateKeyPem: string, issuer: string): GovernanceRule {
  const base: Omit<GovernanceRule, "signature"> = {
    id: "mvp-rule-allow-read",
    version: "1.0.0",
    name: "MVP read rule",
    status: "active",
    issuer,
    precedence: 10,
    effectiveFrom: BOOTSTRAP_AT,
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    provenance: "giia-mvp-bootstrap",
  };

  return {
    ...base,
    signature: signGovernanceRule(base, privateKeyPem),
  };
}

function constitutionalRule(
  privateKeyPem: string,
  issuer: string,
): ConstitutionalRule {
  const base: Omit<ConstitutionalRule, "signature"> = {
    id: "mvp-constitution-allow-read",
    version: "1.0.0",
    name: "MVP constitutional read rule",
    scope: "global",
    issuer,
    precedence: 100,
    effectiveFrom: BOOTSTRAP_AT,
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    immutablePrinciples: [
      "HUMAN_SAFETY_FIRST",
      "EVIDENCE_BEFORE_ACTION",
      "HUMAN_ACCOUNTABILITY",
    ],
    provenance: "giia-mvp-bootstrap",
    status: "active",
  };

  return {
    ...base,
    signature: signConstitutionalRule(base, privateKeyPem),
  };
}

function makeEvidence(
  identityId: string,
  requestId: string,
  action: string,
  resource: string,
  issuedAt: string,
): Evidence {
  const base: Omit<Evidence, "recordHash"> = {
    id: `mvp-evidence-${requestId}`,
    kind: "event",
    subject: identityId,
    authorizationRequestId: requestId,
    action,
    occurredAt: issuedAt,
    recordedAt: issuedAt,
    source: "giia-mvp-api",
    contentHash: "mvp-request-content",
    provenance: "giia-mvp-api",
  };

  return {
    ...base,
    recordHash: createEvidenceHash(base),
  };
}

function makeAudit(
  identityId: string,
  requestId: string,
  evidenceId: string,
  action: string,
  resource: string,
  issuedAt: string,
): AuditEvent {
  const base: Omit<AuditEvent, "recordHash"> = {
    id: `mvp-audit-${requestId}`,
    actor: identityId,
    authorizationRequestId: requestId,
    evidenceId,
    action,
    resource,
    outcome: "EVALUATED",
    occurredAt: issuedAt,
    recordedAt: issuedAt,
    reason: "GIIA authoritative evaluation; no execution occurred",
    provenance: "giia-mvp-api",
  };

  return {
    ...base,
    recordHash: createAuditHash(base),
  };
}

export function createMvpComposition(
  options: MvpCompositionOptions = {},
): MvpComposition {
  const id = identity();
  const auth = authority(id.id);

  const durable = options.durableBootstrap === true;

  const bootstrapPaths = options.bootstrapPaths ?? {
    keystorePath:
      "runtime-data/mvp-bootstrap.keystore",
    trustRegistryPath:
      "runtime-data/mvp-trust.db",
  };

  const trustRegistryPath = durable
    ? bootstrapPaths.trustRegistryPath
    : (options.trustRegistryPath ?? ":memory:");

  /*
   * Classify durable filesystem state before opening SQLite.
   * DatabaseSync creates the registry file when opened, so checking
   * existence after construction would falsely classify a fresh
   * bootstrap as partial state.
   */
  const durableKeystoreExists = durable
    ? existsSync(bootstrapPaths.keystorePath)
    : false;

  const durableRegistryExists = durable
    ? existsSync(bootstrapPaths.trustRegistryPath)
    : false;

  if (
    durable &&
    durableKeystoreExists !== durableRegistryExists
  ) {
    throw new Error(
      "DURABLE_BOOTSTRAP_PARTIAL_STATE",
    );
  }

  /*
   * Initialize durable bootstrap before SQLite opens the trust registry.
   * SQLite creates the registry file on construction.
   */
  let initialDurableState: DurableBootstrapState | undefined;

  if (
    durable &&
    !durableKeystoreExists &&
    !durableRegistryExists
  ) {
    initialDurableState = initializeDurableBootstrap(
      bootstrapPaths,
      BOOTSTRAP_AT,
    );
  }

  const trustRegistry = new TrustRegistry(
    trustRegistryPath,
  );

  const evidenceAuditRegistry =
    new EvidenceAuditRegistry(
      options.evidenceAuditRegistryPath ?? ":memory:",
    );

  let chain: {
    trustChain: TrustChainInput;
    delegationPrivateKeyPem: string;
    governanceKey: ReturnType<typeof createTrustKey>["key"];
    governancePrivateKeyPem: string;
    boundary: KeySecurityBoundary;
    governanceAuthoritySet: GovernanceAuthoritySet;
    governanceAuthorityMembers: readonly GovernanceAuthorityKeyPair[];
  };

  try {
    if (!durable) {
      chain = createEphemeralChain(
        id.id,
        auth.id,
      );

      trustRegistry.putKey(
        chain.trustChain.rootKey,
      );
      trustRegistry.putKey(
        chain.trustChain.anchorKey,
      );
      trustRegistry.putKey(
        chain.trustChain.delegationKey,
      );
      trustRegistry.putKey(
        chain.governanceKey,
      );
      trustRegistry.putRoot(
        chain.trustChain.root,
      );
      trustRegistry.putAnchor(
        chain.trustChain.anchor,
      );
      trustRegistry.putDelegation(
        chain.trustChain.delegation,
      );
      trustRegistry.putCredential(
        chain.trustChain.credential,
      );
    } else {
      const keystoreExists =
        durableKeystoreExists;
      const registryExists =
        durableRegistryExists;

      if (!keystoreExists && !registryExists) {
        const state = initialDurableState;

        if (!state) {
          throw new Error(
            "DURABLE_BOOTSTRAP_INITIALIZATION_MISSING",
          );
        }

        chain = createDurableChain(
          id.id,
          auth.id,
          state,
        );

        trustRegistry.ensureKey(
          state.keys.root,
        );
        trustRegistry.ensureKey(
          state.keys.anchor,
        );
        trustRegistry.ensureKey(
          state.keys.delegation,
        );
        trustRegistry.ensureKey(
          state.keys.governance,
        );
        trustRegistry.ensureRoot(
          chain.trustChain.root,
        );
        trustRegistry.ensureAnchor(
          chain.trustChain.anchor,
        );
        trustRegistry.ensureDelegation(
          chain.trustChain.delegation,
        );
        trustRegistry.ensureCredential(
          chain.trustChain.credential,
        );
      } else {
        const rootKey =
          trustRegistry.getKey(
            "mvp-root-key",
          );
        const anchorKey =
          trustRegistry.getKey(
            "mvp-anchor-key",
          );
        const delegationKey =
          trustRegistry.getKey(
            "mvp-delegation-key",
          );
        const governanceKey =
          trustRegistry.getKey(
            "mvp-governance-key",
          );

        if (
          !rootKey ||
          !anchorKey ||
          !delegationKey ||
          !governanceKey
        ) {
          throw new Error(
            "DURABLE_TRUST_STATE_INCOMPLETE",
          );
        }

        const state =
          loadDurableBootstrap(
            bootstrapPaths,
            {
              root: rootKey,
              anchor: anchorKey,
              delegation: delegationKey,
              governance: governanceKey,
            },
          );

        const persistedChain =
          loadPersistedDurableChain(
            trustRegistry,
            state,
          );

        const governanceBoundary =
          new KeySecurityBoundary();

        governanceBoundary.register(
          state.keys.governance,
          state.privateKeys
            .governancePrivateKeyPem,
          BOOTSTRAP_AT,
        );

        chain = {
          trustChain: persistedChain,
          delegationPrivateKeyPem:
            state.privateKeys
              .delegationPrivateKeyPem,
          governanceKey:
            state.keys.governance,
          governancePrivateKeyPem:
            state.privateKeys
              .governancePrivateKeyPem,
          boundary: governanceBoundary,
          governanceAuthoritySet:
            state.governanceAuthority.authoritySet,
          governanceAuthorityMembers:
            state.governanceAuthority.members,
        };
      }
    }

    const delegationBoundary =
      new KeySecurityBoundary();

    delegationBoundary.register(
      chain.trustChain.delegationKey,
      chain.delegationPrivateKeyPem,
      BOOTSTRAP_AT,
    );

    const governanceAuthorization =
      createGovernanceKeyAuthorization({
        authorizationId:
          "mvp-governance-authorization-001",
        governanceKey:
          chain.governanceKey,
        credential:
          chain.trustChain.credential,
        signingAuthorityId:
          chain.trustChain.delegation.delegateeId,
        issuerDelegationKey:
          chain.trustChain.delegationKey,
        trustChain:
          chain.trustChain,
        boundary: delegationBoundary,
        issuedAt: BOOTSTRAP_AT,
        expiresAt:
          "2036-01-01T00:00:00.000Z",
      });

    const governanceRules = [
      governanceRule(
        chain.delegationPrivateKeyPem,
        chain.trustChain.delegation
          .delegateeId,
      ),
    ];

    const constitutionalRules = [
      constitutionalRule(
        chain.delegationPrivateKeyPem,
        chain.trustChain.delegation
          .delegateeId,
      ),
    ];

    return {
      evaluate(input) {
        if (
          !trustRegistry.consumeReplay(
            input.requestId,
            input.requestedAt,
          )
        ) {
          throw new Error(
            "REPLAY_REQUEST_REJECTED",
          );
        }

        const authorizationRequest:
          AuthorizationRequest = {
          id: input.requestId,
          subjectIdentityId: id.id,
          authorityId: auth.id,
          action: input.action,
          resource: input.resource,
          requestedAt: input.requestedAt,
        };

        const action: ActionIntent = {
          id: `mvp-action-${input.requestId}`,
          authorizationRequestId:
            input.requestId,
          actor: id.id,
          action: input.action,
          resource: input.resource,
          provenance: "giia-mvp-api",
        };

        const evidence = makeEvidence(
          id.id,
          input.requestId,
          input.action,
          input.resource,
          input.requestedAt,
        );

        const audit = makeAudit(
          id.id,
          input.requestId,
          evidence.id,
          input.action,
          input.resource,
          input.requestedAt,
        );

        return evaluateTrustToAction({
          identity: id,
          authority: auth,
          trustChain: {
            ...chain.trustChain,
            at: input.requestedAt,
          },
          trustRegistry,
          binding: {
            credentialId:
              chain.trustChain.credential.id,
            authorityId: auth.id,
          },
          authorizationRequest,
          governanceRules,
          constitutionalRules,
          action,
          evidence,
          audit,
          evidenceAuditRegistry,
        });
      },

      createDecisionRecord(
        result,
        requestId,
        action,
        resource,
        issuedAt,
      ) {
        return createDecisionRecord(
          result,
          requestId,
          action,
          resource,
          issuedAt,
          {
            authorization:
              governanceAuthorization,
            governanceKey:
              chain.governanceKey,
            credential:
              chain.trustChain.credential,
            trustChain:
              chain.trustChain,
            signingAuthorityId:
              chain.trustChain.delegation
                .delegateeId,
            boundary: chain.boundary,
            governanceAuthoritySet:
              chain.governanceAuthoritySet,
            governanceAuthorityMembers:
              chain.governanceAuthorityMembers,
          },
        );
      },

      close() {
        evidenceAuditRegistry.close();
        trustRegistry.close();
      },
    };
  } catch (error) {
    evidenceAuditRegistry.close();
    trustRegistry.close();
    throw error;
  }
}
