import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { canonicalize } from "../core/canonical.js";

export const GOVERNANCE_QUORUM = 3 as const;
export const GOVERNANCE_MEMBER_COUNT = 5 as const;

export type GovernanceMemberStatus =
  | "active"
  | "revoked"
  | "quarantined"
  | "expired";

export interface GovernanceQuorumMember {
  readonly memberId: string;
  readonly purpose: "governance";
  readonly status: GovernanceMemberStatus;
  readonly publicKeyPem: string;
}

export interface GovernanceQuorumSignature {
  readonly memberId: string;
  readonly signatureBase64: string;
}

export interface GovernanceQuorumCertificate {
  readonly algorithm: "Ed25519-QUORUM-3-OF-5";
  readonly quorum: 3;
  readonly memberCount: 5;
  readonly decisionDigest: string;
  readonly signatures: readonly GovernanceQuorumSignature[];
}

export interface GovernanceQuorumVerification {
  readonly valid: boolean;
  readonly reason: string;
  readonly decisionDigest: string;
}

export interface GovernanceQuorumKeyPair {
  readonly member: GovernanceQuorumMember;
  readonly privateKeyPem: string;
}

export function governanceDecisionDigest(
  decision: unknown,
): string {
  return createHash("sha256")
    .update(canonicalize(decision), "utf8")
    .digest("hex");
}

export function generateGovernanceQuorumMember(
  memberId: string,
): GovernanceQuorumKeyPair {
  if (memberId.trim() === "") {
    throw new Error("GOVERNANCE_MEMBER_ID_REQUIRED");
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

export function signGovernanceQuorumMember(
  decision: unknown,
  member: GovernanceQuorumKeyPair,
): GovernanceQuorumSignature {
  const digest = governanceDecisionDigest(decision);

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

export function createGovernanceQuorumCertificate(
  decision: unknown,
  members: readonly GovernanceQuorumKeyPair[],
): GovernanceQuorumCertificate {
  if (members.length !== GOVERNANCE_MEMBER_COUNT) {
    throw new Error("GOVERNANCE_QUORUM_REQUIRES_EXACTLY_FIVE_MEMBERS");
  }

  const signatures = members
    .slice(0, GOVERNANCE_QUORUM)
    .map((member) =>
      signGovernanceQuorumMember(decision, member),
    );

  return Object.freeze({
    algorithm: "Ed25519-QUORUM-3-OF-5" as const,
    quorum: GOVERNANCE_QUORUM,
    memberCount: GOVERNANCE_MEMBER_COUNT,
    decisionDigest: governanceDecisionDigest(decision),
    signatures: Object.freeze(signatures),
  });
}

export function verifyGovernanceQuorumCertificate(
  decision: unknown,
  certificate: GovernanceQuorumCertificate,
  members: readonly GovernanceQuorumMember[],
): GovernanceQuorumVerification {
  const expectedDigest = governanceDecisionDigest(decision);

  if (
    certificate.algorithm !== "Ed25519-QUORUM-3-OF-5" ||
    certificate.quorum !== GOVERNANCE_QUORUM ||
    certificate.memberCount !== GOVERNANCE_MEMBER_COUNT
  ) {
    return {
      valid: false,
      reason: "GOVERNANCE_QUORUM_PARAMETERS_INVALID",
      decisionDigest: expectedDigest,
    };
  }

  if (certificate.decisionDigest !== expectedDigest) {
    return {
      valid: false,
      reason: "GOVERNANCE_QUORUM_DECISION_DIGEST_MISMATCH",
      decisionDigest: expectedDigest,
    };
  }

  if (members.length !== GOVERNANCE_MEMBER_COUNT) {
    return {
      valid: false,
      reason: "GOVERNANCE_QUORUM_MEMBER_SET_INVALID",
      decisionDigest: expectedDigest,
    };
  }

  const registered = new Map(
    members.map((member) => [member.memberId, member]),
  );

  const seen = new Set<string>();

  for (const signature of certificate.signatures) {
    if (seen.has(signature.memberId)) {
      return {
        valid: false,
        reason: "GOVERNANCE_QUORUM_DUPLICATE_SIGNER",
        decisionDigest: expectedDigest,
      };
    }

    seen.add(signature.memberId);

    const member = registered.get(signature.memberId);

    if (!member) {
      return {
        valid: false,
        reason: "GOVERNANCE_QUORUM_SIGNER_NOT_REGISTERED",
        decisionDigest: expectedDigest,
      };
    }

    if (member.purpose !== "governance") {
      return {
        valid: false,
        reason: "GOVERNANCE_QUORUM_SIGNER_PURPOSE_INVALID",
        decisionDigest: expectedDigest,
      };
    }

    if (member.status !== "active") {
      return {
        valid: false,
        reason: "GOVERNANCE_QUORUM_SIGNER_NOT_ACTIVE",
        decisionDigest: expectedDigest,
      };
    }

    let publicKey: KeyObject;

    try {
      publicKey = createPublicKey(member.publicKeyPem);
    } catch {
      return {
        valid: false,
        reason: "GOVERNANCE_QUORUM_PUBLIC_KEY_INVALID",
        decisionDigest: expectedDigest,
      };
    }

    const validSignature = verify(
      null,
      Buffer.from(expectedDigest, "utf8"),
      publicKey,
      Buffer.from(signature.signatureBase64, "base64"),
    );

    if (!validSignature) {
      return {
        valid: false,
        reason: "GOVERNANCE_QUORUM_SIGNATURE_INVALID",
        decisionDigest: expectedDigest,
      };
    }
  }

  if (seen.size < GOVERNANCE_QUORUM) {
    return {
      valid: false,
      reason: "GOVERNANCE_QUORUM_THRESHOLD_NOT_MET",
      decisionDigest: expectedDigest,
    };
  }

  return {
    valid: true,
    reason: "GOVERNANCE_QUORUM_VERIFIED",
    decisionDigest: expectedDigest,
  };
}
