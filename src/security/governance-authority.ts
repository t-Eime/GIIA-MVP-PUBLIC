import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { canonicalize } from "../core/canonical.js";

export const GOVERNANCE_AUTHORITY_QUORUM = 3 as const;
export const GOVERNANCE_AUTHORITY_MEMBER_COUNT = 5 as const;

export type GovernanceAuthorityMemberStatus =
  | "active"
  | "revoked"
  | "quarantined"
  | "expired";

export interface GovernanceAuthorityMember {
  readonly memberId: string;
  readonly purpose: "governance";
  readonly status: GovernanceAuthorityMemberStatus;
  readonly publicKeyPem: string;
}

export interface GovernanceAuthoritySet {
  readonly setId: string;
  readonly version: number;
  readonly quorum: 3;
  readonly memberCount: 5;
  readonly members: readonly GovernanceAuthorityMember[];
  readonly fingerprint: string;
}

export interface GovernanceAuthoritySignature {
  readonly memberId: string;
  readonly signatureBase64: string;
}

export interface GovernanceAuthorityCertificate {
  readonly algorithm: "ED25519-MULTISIG-3-OF-5";
  readonly setId: string;
  readonly setVersion: number;
  readonly decisionDigest: string;
  readonly signatures: readonly GovernanceAuthoritySignature[];
}

export interface GovernanceAuthorityKeyPair {
  readonly member: GovernanceAuthorityMember;
  readonly privateKeyPem: string;
}

export interface GovernanceAuthorityVerification {
  readonly valid: boolean;
  readonly reason: string;
  readonly decisionDigest: string;
}

export function governanceAuthorityDecisionDigest(
  decision: unknown,
): string {
  return createHash("sha256")
    .update(canonicalize(decision), "utf8")
    .digest("hex");
}

export function governanceAuthoritySetFingerprint(
  setWithoutFingerprint: Omit<GovernanceAuthoritySet, "fingerprint">,
): string {
  return createHash("sha256")
    .update(canonicalize(setWithoutFingerprint), "utf8")
    .digest("hex");
}

export function generateGovernanceAuthorityMember(
  memberId: string,
): GovernanceAuthorityKeyPair {
  if (memberId.trim() === "") {
    throw new Error("GOVERNANCE_AUTHORITY_MEMBER_ID_REQUIRED");
  }

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  return {
    member: Object.freeze({
      memberId,
      purpose: "governance" as const,
      status: "active" as const,
      publicKeyPem: publicKey.export({
        type: "spki",
        format: "pem",
      }).toString(),
    }),
    privateKeyPem: privateKey.export({
      type: "pkcs8",
      format: "pem",
    }).toString(),
  };
}

export function createGovernanceAuthoritySet(
  setId: string,
  version: number,
  members: readonly GovernanceAuthorityMember[],
): GovernanceAuthoritySet {
  if (setId.trim() === "") {
    throw new Error("GOVERNANCE_AUTHORITY_SET_ID_REQUIRED");
  }

  if (!Number.isInteger(version) || version < 1) {
    throw new Error("GOVERNANCE_AUTHORITY_SET_VERSION_INVALID");
  }

  if (members.length !== GOVERNANCE_AUTHORITY_MEMBER_COUNT) {
    throw new Error(
      "GOVERNANCE_AUTHORITY_REQUIRES_EXACTLY_FIVE_MEMBERS",
    );
  }

  const ids = new Set<string>();

  for (const member of members) {
    if (ids.has(member.memberId)) {
      throw new Error("GOVERNANCE_AUTHORITY_DUPLICATE_MEMBER");
    }

    ids.add(member.memberId);

    if (member.purpose !== "governance") {
      throw new Error("GOVERNANCE_AUTHORITY_MEMBER_PURPOSE_INVALID");
    }

    createPublicKey(member.publicKeyPem);
  }

  const base = {
    setId,
    version,
    quorum: GOVERNANCE_AUTHORITY_QUORUM,
    memberCount: GOVERNANCE_AUTHORITY_MEMBER_COUNT,
    members,
  };

  return Object.freeze({
    ...base,
    fingerprint: governanceAuthoritySetFingerprint(base),
  });
}

export function signGovernanceAuthorityMember(
  decision: unknown,
  member: GovernanceAuthorityKeyPair,
): GovernanceAuthoritySignature {
  const digest = governanceAuthorityDecisionDigest(decision);

  const signature = sign(
    null,
    Buffer.from(digest, "utf8"),
    member.privateKeyPem,
  );

  return Object.freeze({
    memberId: member.member.memberId,
    signatureBase64: signature.toString("base64"),
  });
}

export function createGovernanceAuthorityCertificate(
  decision: unknown,
  authoritySet: GovernanceAuthoritySet,
  signers: readonly GovernanceAuthorityKeyPair[],
): GovernanceAuthorityCertificate {
  if (
    authoritySet.memberCount !==
    GOVERNANCE_AUTHORITY_MEMBER_COUNT
  ) {
    throw new Error(
      "GOVERNANCE_AUTHORITY_MEMBER_COUNT_INVALID",
    );
  }

  if (authoritySet.quorum !== GOVERNANCE_AUTHORITY_QUORUM) {
    throw new Error(
      "GOVERNANCE_AUTHORITY_QUORUM_INVALID",
    );
  }

  if (signers.length < GOVERNANCE_AUTHORITY_QUORUM) {
    throw new Error(
      "GOVERNANCE_AUTHORITY_QUORUM_NOT_MET",
    );
  }

  const registered = new Map(
    authoritySet.members.map((member) => [
      member.memberId,
      member,
    ]),
  );

  const seen = new Set<string>();

  for (const signer of signers) {
    if (seen.has(signer.member.memberId)) {
      throw new Error(
        "GOVERNANCE_AUTHORITY_DUPLICATE_SIGNER",
      );
    }

    const registeredMember = registered.get(
      signer.member.memberId,
    );

    if (!registeredMember) {
      throw new Error(
        "GOVERNANCE_AUTHORITY_SIGNER_NOT_REGISTERED",
      );
    }

    if (registeredMember.status !== "active") {
      throw new Error(
        "GOVERNANCE_AUTHORITY_SIGNER_NOT_ACTIVE",
      );
    }

    if (
      registeredMember.publicKeyPem !==
      signer.member.publicKeyPem
    ) {
      throw new Error(
        "GOVERNANCE_AUTHORITY_SIGNER_KEY_MISMATCH",
      );
    }

    seen.add(signer.member.memberId);
  }

  if (seen.size < GOVERNANCE_AUTHORITY_QUORUM) {
    throw new Error(
      "GOVERNANCE_AUTHORITY_QUORUM_NOT_MET",
    );
  }

  const signatures = signers.map((signer) =>
    signGovernanceAuthorityMember(decision, signer),
  );

  return Object.freeze({
    algorithm: "ED25519-MULTISIG-3-OF-5" as const,
    setId: authoritySet.setId,
    setVersion: authoritySet.version,
    decisionDigest:
      governanceAuthorityDecisionDigest(decision),
    signatures: Object.freeze(signatures),
  });
}

export function verifyGovernanceAuthorityCertificate(
  decision: unknown,
  certificate: GovernanceAuthorityCertificate,
  authoritySet: GovernanceAuthoritySet,
): GovernanceAuthorityVerification {
  const expectedDigest =
    governanceAuthorityDecisionDigest(decision);

  if (
    certificate.algorithm !==
    "ED25519-MULTISIG-3-OF-5"
  ) {
    return {
      valid: false,
      reason: "GOVERNANCE_AUTHORITY_ALGORITHM_INVALID",
      decisionDigest: expectedDigest,
    };
  }

  if (
    certificate.setId !== authoritySet.setId ||
    certificate.setVersion !== authoritySet.version
  ) {
    return {
      valid: false,
      reason: "GOVERNANCE_AUTHORITY_SET_MISMATCH",
      decisionDigest: expectedDigest,
    };
  }

  if (
    authoritySet.quorum !==
      GOVERNANCE_AUTHORITY_QUORUM ||
    authoritySet.memberCount !==
      GOVERNANCE_AUTHORITY_MEMBER_COUNT
  ) {
    return {
      valid: false,
      reason: "GOVERNANCE_AUTHORITY_PARAMETERS_INVALID",
      decisionDigest: expectedDigest,
    };
  }

  const recomputedFingerprint =
    governanceAuthoritySetFingerprint({
      setId: authoritySet.setId,
      version: authoritySet.version,
      quorum: authoritySet.quorum,
      memberCount: authoritySet.memberCount,
      members: authoritySet.members,
    });

  if (recomputedFingerprint !== authoritySet.fingerprint) {
    return {
      valid: false,
      reason: "GOVERNANCE_AUTHORITY_SET_FINGERPRINT_INVALID",
      decisionDigest: expectedDigest,
    };
  }

  if (certificate.decisionDigest !== expectedDigest) {
    return {
      valid: false,
      reason: "GOVERNANCE_AUTHORITY_DECISION_DIGEST_MISMATCH",
      decisionDigest: expectedDigest,
    };
  }

  if (
    certificate.signatures.length <
    GOVERNANCE_AUTHORITY_QUORUM
  ) {
    return {
      valid: false,
      reason: "GOVERNANCE_AUTHORITY_QUORUM_NOT_MET",
      decisionDigest: expectedDigest,
    };
  }

  const registered = new Map(
    authoritySet.members.map((member) => [
      member.memberId,
      member,
    ]),
  );

  const seen = new Set<string>();

  for (const signature of certificate.signatures) {
    if (seen.has(signature.memberId)) {
      return {
        valid: false,
        reason: "GOVERNANCE_AUTHORITY_DUPLICATE_SIGNER",
        decisionDigest: expectedDigest,
      };
    }

    seen.add(signature.memberId);

    const member = registered.get(signature.memberId);

    if (!member) {
      return {
        valid: false,
        reason: "GOVERNANCE_AUTHORITY_SIGNER_NOT_REGISTERED",
        decisionDigest: expectedDigest,
      };
    }

    if (member.purpose !== "governance") {
      return {
        valid: false,
        reason: "GOVERNANCE_AUTHORITY_SIGNER_PURPOSE_INVALID",
        decisionDigest: expectedDigest,
      };
    }

    if (member.status !== "active") {
      return {
        valid: false,
        reason: "GOVERNANCE_AUTHORITY_SIGNER_NOT_ACTIVE",
        decisionDigest: expectedDigest,
      };
    }

    let publicKey: KeyObject;

    try {
      publicKey = createPublicKey(member.publicKeyPem);
    } catch {
      return {
        valid: false,
        reason: "GOVERNANCE_AUTHORITY_PUBLIC_KEY_INVALID",
        decisionDigest: expectedDigest,
      };
    }

    const validSignature = verify(
      null,
      Buffer.from(expectedDigest, "utf8"),
      publicKey,
      Buffer.from(
        signature.signatureBase64,
        "base64",
      ),
    );

    if (!validSignature) {
      return {
        valid: false,
        reason: "GOVERNANCE_AUTHORITY_SIGNATURE_INVALID",
        decisionDigest: expectedDigest,
      };
    }
  }

  return {
    valid: true,
    reason: "GOVERNANCE_AUTHORITY_VERIFIED",
    decisionDigest: expectedDigest,
  };
}
