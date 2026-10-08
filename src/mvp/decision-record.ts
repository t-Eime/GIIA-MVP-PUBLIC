import type { TrustToActionResult } from "../trust-action/types.js";
import type { TrustChainInput } from "../trust/service.js";
import type { TrustCredential, TrustKey } from "../trust/types.js";
import type { KeySecurityBoundary } from "../security/key-boundary.js";

import {
  governanceKeyAuthorizationFingerprint,
  verifyGovernanceKeyAuthorization,
  type SignedGovernanceKeyAuthorization,
} from "../governance-decision/authorization.js";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { canonicalize } from "../core/canonical.js";
import { verifyCanonical } from "../trust/crypto.js";

import {
  createGovernanceAuthorityCertificate,
  verifyGovernanceAuthorityCertificate,
  GOVERNANCE_AUTHORITY_QUORUM,
  type GovernanceAuthorityCertificate,
  type GovernanceAuthorityKeyPair,
  type GovernanceAuthoritySet,
} from "../security/governance-authority.js";

import type { MvpDecisionRecord } from "./types.js";

export interface MvpDecisionSigningContext {
  authorization: SignedGovernanceKeyAuthorization;
  governanceKey: TrustKey;
  credential: TrustCredential;
  trustChain: TrustChainInput;
  signingAuthorityId: string;
  boundary: KeySecurityBoundary;
  governanceAuthoritySet: GovernanceAuthoritySet;
  governanceAuthorityMembers: readonly GovernanceAuthorityKeyPair[];
}

function unsignedRecord(
  result: TrustToActionResult,
  requestId: string,
  action: string,
  resource: string,
  issuedAt: string,
  context: MvpDecisionSigningContext,
) {
  return {
    version: "1" as const,
    recordType: "GIIA_AUTHORITATIVE_DECISION" as const,

    decisionId: randomUUID(),
    requestId,
    action,
    resource,

    executionBinding: {
      actorId: result.action?.actor ?? "mvp-identity-001",
      target: resource,
      payloadHash: createHash("sha256")
        .update(
          canonicalize({
            requestId,
            action,
            resource,
          }),
          "utf8",
        )
        .digest("hex"),
      constitutionVersion: "GIIA-CONST-0.1.1",
      nonce: randomBytes(32).toString("hex"),
      expiresAt: new Date(
        Date.parse(issuedAt) + 5 * 60 * 1000,
      ).toISOString(),
    },

    decision: result.decision,
    reason: result.reason,

    authoritative: true as const,
    executionPermitted: false as const,

    provenance:
      result.action?.provenance ??
      "giia-mvp-authoritative-pipeline",

    issuedAt,

    signerKeyId: context.governanceKey.id,
    signerPublicKeyPem: context.governanceKey.publicKeyPem,

    governanceAuthorization: context.authorization,

    governanceAuthorizationFingerprint:
      governanceKeyAuthorizationFingerprint(
        context.authorization,
      ),

    governanceKey: context.governanceKey,
    governanceCredential: context.credential,
    governanceTrustChain: context.trustChain,
    signingAuthorityId: context.signingAuthorityId,

    governanceAuthoritySet:
      context.governanceAuthoritySet,
  };
}

export function createDecisionRecord(
  result: TrustToActionResult,
  requestId: string,
  action: string,
  resource: string,
  issuedAt: string,
  context: MvpDecisionSigningContext,
): MvpDecisionRecord {
  if (
    result.decision !== "ALLOW" &&
    result.decision !== "DENY" &&
    result.decision !== "DEFER"
  ) {
    throw new Error("MVP_INVALID_AUTHORITATIVE_DECISION");
  }

  const authorized = verifyGovernanceKeyAuthorization({
    authorization: context.authorization,
    governanceKey: context.governanceKey,
    credential: context.credential,
    trustChain: context.trustChain,
    at: issuedAt,
  });

  if (!authorized) {
    throw new Error("MVP_GOVERNANCE_AUTHORIZATION_INVALID");
  }

  const base = unsignedRecord(
    result,
    requestId,
    action,
    resource,
    issuedAt,
    context,
  );

  const activeAuthorityMembers =
    context.governanceAuthorityMembers
      .filter(
        (member) =>
          member.member.status === "active",
      )
      .slice(0, GOVERNANCE_AUTHORITY_QUORUM);

  if (
    activeAuthorityMembers.length <
    GOVERNANCE_AUTHORITY_QUORUM
  ) {
    throw new Error(
      "MVP_GOVERNANCE_AUTHORITY_QUORUM_NOT_AVAILABLE",
    );
  }

  const governanceAuthorityCertificate =
    createGovernanceAuthorityCertificate(
      base,
      context.governanceAuthoritySet,
      activeAuthorityMembers,
    );

  const completedUnsignedRecord = {
    ...base,
    governanceAuthorityCertificate,
  };

  const signature = context.boundary.sign(
    context.governanceKey.id,
    "governance",
    completedUnsignedRecord,
    issuedAt,
  );

  return {
    ...completedUnsignedRecord,
    signature,
  };
}

export function verifyDecisionRecordSignature(
  record: MvpDecisionRecord,
): boolean {
  try {
    const {
      signature,
      governanceAuthorityCertificate,
      ...certificateDecisionMaterial
    } = record;

    if (
      !governanceAuthorityCertificate
    ) {
      return false;
    }

    const authorityVerification =
      verifyGovernanceAuthorityCertificate(
        certificateDecisionMaterial,
        governanceAuthorityCertificate,
        record.governanceAuthoritySet,
      );

    if (!authorityVerification.valid) {
      return false;
    }

    const fingerprint =
      governanceKeyAuthorizationFingerprint(
        record.governanceAuthorization,
      );

    if (
      fingerprint !==
      record.governanceAuthorizationFingerprint
    ) {
      return false;
    }

    if (
      record.signerKeyId !==
      record.governanceKey.id
    ) {
      return false;
    }

    if (
      record.signerPublicKeyPem !==
      record.governanceKey.publicKeyPem
    ) {
      return false;
    }

    if (
      record.governanceKey.algorithm !== "Ed25519" ||
      record.governanceKey.purpose !== "governance" ||
      record.governanceKey.status !== "active"
    ) {
      return false;
    }

    if (
      record.governanceAuthorization.payload
        .governanceKeyId !==
      record.governanceKey.id
    ) {
      return false;
    }

    if (
      record.governanceAuthorization.payload
        .governancePublicKeyPem !==
      record.governanceKey.publicKeyPem
    ) {
      return false;
    }

    if (
      record.governanceAuthorization.payload
        .signingAuthorityId !==
      record.signingAuthorityId
    ) {
      return false;
    }

    if (
      !verifyGovernanceKeyAuthorization({
        authorization:
          record.governanceAuthorization,
        governanceKey:
          record.governanceKey,
        credential:
          record.governanceCredential,
        trustChain:
          record.governanceTrustChain,
        at: record.issuedAt,
      })
    ) {
      return false;
    }

    return verifyCanonical(
      {
        ...certificateDecisionMaterial,
        governanceAuthorityCertificate,
      },
      signature,
      record.signerPublicKeyPem,
    );
  } catch {
    return false;
  }
}
