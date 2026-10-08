import { invariant } from "../core/errors.js";
import {
  validateNonEmpty,
  validateTimestamp,
} from "../core/validation.js";
import { canonicalize } from "../core/canonical.js";
import { sha256 } from "../core/security.js";
import {
  generateEd25519KeyPair,
  signCanonical,
  verifyCanonical,
} from "./crypto.js";
import { KeySecurityBoundary } from "../security/key-boundary.js";
import type {
  TrustAnchor,
  TrustCredential,
  TrustDelegation,
  TrustKey,
  TrustRoot,
  TrustStatus,
  TrustVerificationResult,
} from "./types.js";

function activeAt(
  status: TrustStatus,
  notBefore: string,
  notAfter: string | undefined,
  at: string,
): boolean {
  if (status !== "active") return false;
  if (at < notBefore) return false;
  if (notAfter !== undefined && at >= notAfter) return false;
  return true;
}

export function createTrustKey(
  id: string,
  purpose: TrustKey["purpose"],
  provenance: string,
  createdAt: string,
): { key: TrustKey; privateKeyPem: string } {
  validateNonEmpty(id, "TRUST_KEY_ID_EMPTY", "Trust key id is required");
  validateNonEmpty(
    provenance,
    "TRUST_KEY_PROVENANCE_EMPTY",
    "Trust key provenance is required",
  );
  validateTimestamp(
    createdAt,
    "TRUST_KEY_CREATED_AT_INVALID",
    "Trust key creation time is invalid",
  );

  const pair = generateEd25519KeyPair();

  return {
    key: {
      id,
      algorithm: "Ed25519",
      purpose,
      publicKeyPem: pair.publicKeyPem,
      createdAt,
      notBefore: createdAt,
      status: "active",
      provenance,
    },
    privateKeyPem: pair.privateKeyPem,
  };
}

export function validateTrustKey(key: TrustKey): void {
  validateNonEmpty(key.id, "TRUST_KEY_ID_EMPTY", "Trust key id is required");
  validateNonEmpty(
    key.publicKeyPem,
    "TRUST_KEY_PUBLIC_EMPTY",
    "Trust key public key is required",
  );
  validateNonEmpty(
    key.provenance,
    "TRUST_KEY_PROVENANCE_EMPTY",
    "Trust key provenance is required",
  );
  validateTimestamp(
    key.createdAt,
    "TRUST_KEY_CREATED_AT_INVALID",
    "Trust key creation time is invalid",
  );
  validateTimestamp(
    key.notBefore,
    "TRUST_KEY_NOT_BEFORE_INVALID",
    "Trust key notBefore is invalid",
  );

  if (key.notAfter !== undefined) {
    validateTimestamp(
      key.notAfter,
      "TRUST_KEY_NOT_AFTER_INVALID",
      "Trust key notAfter is invalid",
    );

    invariant(
      key.notAfter > key.notBefore,
      "TRUST_KEY_WINDOW_INVALID",
      "Trust key expiry must be after notBefore",
    );
  }

  invariant(
    key.status !== "unknown",
    "TRUST_KEY_STATUS_UNKNOWN",
    "Trust key status cannot be unknown",
  );
}

export function rotateTrustKey(
  oldKey: TrustKey,
  newId: string,
  at: string,
  provenance: string,
): { key: TrustKey; privateKeyPem: string } {
  validateTrustKey(oldKey);

  invariant(
    oldKey.status === "active",
    "TRUST_KEY_ROTATION_SOURCE_INVALID",
    "Only an active trust key may be rotated",
  );

  validateTimestamp(
    at,
    "TRUST_KEY_ROTATION_TIME_INVALID",
    "Rotation time is invalid",
  );

  invariant(
    at >= oldKey.notBefore,
    "TRUST_KEY_ROTATION_TIME_BEFORE_KEY",
    "Rotation cannot occur before key activation",
  );

  const result = createTrustKey(
    newId,
    oldKey.purpose,
    provenance,
    at,
  );

  oldKey.status = "expired";
  oldKey.notAfter = at;

  return result;
}

export function rootPayload(root: TrustRoot): Omit<TrustRoot, never> {
  return root;
}

export function anchorPayload(
  anchor: TrustAnchor,
): Omit<TrustAnchor, "signature"> {
  const { signature: _signature, ...payload } = anchor;
  return payload;
}

export function delegationPayload(
  delegation: TrustDelegation,
): Omit<TrustDelegation, "signature"> {
  const { signature: _signature, ...payload } = delegation;
  return payload;
}

export function credentialPayload(
  credential: TrustCredential,
): Omit<TrustCredential, "signature"> {
  const { signature: _signature, ...payload } = credential;
  return payload;
}

export interface SecureTrustSigner {
  boundary: KeySecurityBoundary;
  keyId: string;
  purpose: TrustKey["purpose"];
  at: string;
}

export function createAnchorWithSecureKey(
  anchor: Omit<TrustAnchor, "signature">,
  signer: SecureTrustSigner,
): TrustAnchor {
  invariant(
    signer.purpose === "root",
    "SECURE_SIGNER_PURPOSE_MISMATCH",
    "Anchor creation requires a root signing key",
  );

  const signature = signer.boundary.sign(
    signer.keyId,
    "root",
    anchor,
    signer.at,
  );

  return { ...anchor, signature };
}

export function createDelegationWithSecureKey(
  delegation: Omit<TrustDelegation, "signature">,
  signer: SecureTrustSigner,
): TrustDelegation {
  invariant(
    signer.purpose === "anchor",
    "SECURE_SIGNER_PURPOSE_MISMATCH",
    "Delegation creation requires an anchor signing key",
  );

  const signature = signer.boundary.sign(
    signer.keyId,
    "anchor",
    delegation,
    signer.at,
  );

  return { ...delegation, signature };
}

export function createCredentialWithSecureKey(
  credential: Omit<TrustCredential, "signature">,
  signer: SecureTrustSigner,
): TrustCredential {
  invariant(
    signer.purpose === "delegation",
    "SECURE_SIGNER_PURPOSE_MISMATCH",
    "Credential creation requires a delegation signing key",
  );

  const signature = signer.boundary.sign(
    signer.keyId,
    "delegation",
    credential,
    signer.at,
  );

  return { ...credential, signature };
}

export function createRoot(
  id: string,
  subject: string,
  keyId: string,
  issuedAt: string,
  provenance: string,
): TrustRoot {
  validateNonEmpty(id, "TRUST_ROOT_ID_EMPTY", "Root id is required");
  validateNonEmpty(subject, "TRUST_ROOT_SUBJECT_EMPTY", "Root subject is required");
  validateNonEmpty(keyId, "TRUST_ROOT_KEY_EMPTY", "Root signing key is required");
  validateNonEmpty(
    provenance,
    "TRUST_ROOT_PROVENANCE_EMPTY",
    "Root provenance is required",
  );
  validateTimestamp(
    issuedAt,
    "TRUST_ROOT_ISSUED_AT_INVALID",
    "Root issuance time is invalid",
  );

  return {
    id,
    subject,
    signingKeyId: keyId,
    issuedAt,
    status: "active",
    provenance,
  };
}

export function verifyAnchor(
  anchor: TrustAnchor,
  rootKey: TrustKey,
  at: string,
): boolean {
  if (anchor.signingKeyId !== rootKey.id) return false;
  if (rootKey.status !== "active") return false;

  if (
    !activeAt(
      rootKey.status,
      rootKey.notBefore,
      rootKey.notAfter,
      at,
    )
  ) {
    return false;
  }

  return verifyCanonical(
    anchorPayload(anchor),
    anchor.signature,
    rootKey.publicKeyPem,
  );
}

export function verifyDelegation(
  delegation: TrustDelegation,
  anchor: TrustAnchor,
  anchorKey: TrustKey,
  at: string,
): boolean {
  if (delegation.signingKeyId !== anchorKey.id) return false;
  if (anchor.status !== "active") return false;

  if (
    anchor.expiresAt !== undefined &&
    at >= anchor.expiresAt
  ) {
    return false;
  }

  if (
    !activeAt(
      anchorKey.status,
      anchorKey.notBefore,
      anchorKey.notAfter,
      at,
    )
  ) {
    return false;
  }

  return verifyCanonical(
    delegationPayload(delegation),
    delegation.signature,
    anchorKey.publicKeyPem,
  );
}

export function verifyCredential(
  credential: TrustCredential,
  delegation: TrustDelegation,
  delegationKey: TrustKey,
  at: string,
): boolean {
  if (credential.status !== "active") return false;

  if (
    credential.expiresAt !== undefined &&
    at >= credential.expiresAt
  ) {
    return false;
  }

  if (delegation.status !== "active") return false;

  if (
    delegation.expiresAt !== undefined &&
    at >= delegation.expiresAt
  ) {
    return false;
  }

  if (
    !activeAt(
      delegationKey.status,
      delegationKey.notBefore,
      delegationKey.notAfter,
      at,
    )
  ) {
    return false;
  }

  return verifyCanonical(
    credentialPayload(credential),
    credential.signature,
    delegationKey.publicKeyPem,
  );
}

export interface TrustChainInput {
  root: TrustRoot;
  rootKey: TrustKey;
  anchor: TrustAnchor;
  anchorKey: TrustKey;
  delegation: TrustDelegation;
  delegationKey: TrustKey;
  credential: TrustCredential;
  at: string;
}

export function verifyTrustChain(
  input: TrustChainInput,
): TrustVerificationResult {
  const {
    root,
    rootKey,
    anchor,
    anchorKey,
    delegation,
    delegationKey,
    credential,
    at,
  } = input;

  if (root.status !== "active") {
    return {
      valid: false,
      reason: "ROOT_NOT_ACTIVE",
      chain: [root.id],
    };
  }

  if (root.signingKeyId !== rootKey.id) {
    return {
      valid: false,
      reason: "ROOT_SIGNING_KEY_MISMATCH",
      chain: [root.id],
    };
  }

  if (anchor.rootId !== root.id) {
    return {
      valid: false,
      reason: "ANCHOR_ROOT_BINDING_INVALID",
      chain: [root.id, anchor.id],
    };
  }

  if (!verifyAnchor(anchor, rootKey, at)) {
    return {
      valid: false,
      reason: "ANCHOR_SIGNATURE_INVALID",
      chain: [root.id, anchor.id],
    };
  }

  if (delegation.issuerAnchorId !== anchor.id) {
    return {
      valid: false,
      reason: "DELEGATION_ISSUER_BINDING_INVALID",
      chain: [root.id, anchor.id, delegation.id],
    };
  }

  if (!verifyDelegation(delegation, anchor, anchorKey, at)) {
    return {
      valid: false,
      reason: "DELEGATION_SIGNATURE_INVALID",
      chain: [root.id, anchor.id, delegation.id],
    };
  }

  if (delegation.signingKeyId !== anchorKey.id) {
    return {
      valid: false,
      reason: "DELEGATION_SIGNING_KEY_MISMATCH",
      chain: [root.id, anchor.id, delegation.id],
    };
  }

  if (credential.issuerDelegationId !== delegation.id) {
    return {
      valid: false,
      reason: "CREDENTIAL_ISSUER_BINDING_INVALID",
      chain: [root.id, anchor.id, delegation.id, credential.id],
    };
  }

  if (delegation.delegateeId !== credential.subject) {
    return {
      valid: false,
      reason: "CREDENTIAL_SUBJECT_DELEGATION_BINDING_INVALID",
      chain: [root.id, anchor.id, delegation.id, credential.id],
    };
  }

  if (!verifyCredential(credential, delegation, delegationKey, at)) {
    return {
      valid: false,
      reason: "CREDENTIAL_SIGNATURE_INVALID",
      chain: [root.id, anchor.id, delegation.id, credential.id],
    };
  }

  return {
    valid: true,
    reason: "TRUST_CHAIN_VALID",
    chain: [root.id, anchor.id, delegation.id, credential.id],
  };
}

export function trustFingerprint(value: unknown): string {
  return sha256(canonicalize(value));
}
