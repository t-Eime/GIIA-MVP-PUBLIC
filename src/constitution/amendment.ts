import { canonicalize } from "../core/canonical.js";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import {
  compareConstitutionalVersions,
  type NoDowngradeViolation,
} from "./no-downgrade.js";
import type { ConstitutionalInvariant } from "./invariant-registry.js";
import type { Identity } from "../identity/types.js";
import type { Authority } from "../authority/types.js";
import { isUsableIdentity } from "../identity/service.js";
import { authorize } from "../authorization/service.js";
import { isUsableAuthority } from "../authority/service.js";
import {
  verifyTrustChain,
  type TrustChainInput,
} from "../trust/service.js";
import type { TrustKey } from "../trust/types.js";
import { KeySecurityBoundary } from "../security/key-boundary.js";
import {
  verifyGovernanceAuthorityCertificate,
  type GovernanceAuthorityCertificate,
  type GovernanceAuthoritySet,
} from "../security/governance-authority.js";

export type ConstitutionalAmendmentDecision =
  | "APPROVED"
  | "DENIED";

export interface ConstitutionalHumanApproval {
  readonly approverId: string;
  readonly authorityId: string;
  readonly approvedAt: string;
  readonly signatureAlgorithm: "Ed25519";
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly publicKeyFingerprint: string;
  readonly signatureBase64: string;
}

export interface ConstitutionalAmendmentProposal {
  readonly amendmentId: string;
  readonly baseVersion: string;
  readonly proposedVersion: string;
  readonly reason: string;
  readonly proposerId: string;
  readonly proposedAt: string;
  readonly baseline: readonly ConstitutionalInvariant[];
  readonly proposed: readonly ConstitutionalInvariant[];
  readonly governanceAuthoritySet: GovernanceAuthoritySet;
  readonly governanceAuthorityCertificate: GovernanceAuthorityCertificate;
  readonly approval: ConstitutionalHumanApproval;
}

export interface ConstitutionalAmendmentEvidence {
  readonly evidenceId: string;
  readonly amendmentId: string;
  readonly baseVersion: string;
  readonly proposedVersion: string;
  readonly proposalHash: string;
  readonly approvalHash: string;
  readonly decision: ConstitutionalAmendmentDecision;
  readonly committedAt: string;
  readonly previousEvidenceHash: string | null;
  readonly evidenceHash: string;
}

export interface ConstitutionalAmendmentResult {
  readonly allowed: boolean;
  readonly decision: ConstitutionalAmendmentDecision;
  readonly violations: readonly NoDowngradeViolation[];
  readonly evidence: ConstitutionalAmendmentEvidence | null;
}

const amendmentLedger: ConstitutionalAmendmentEvidence[] = [];
const committedAmendments = new Set<string>();



function sha256(value: unknown): string {
  return createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex");
}

function publicKeyFingerprint(publicKeyPem: string): string {
  return createHash("sha256")
    .update(publicKeyPem, "utf8")
    .digest("hex");
}

function assertNonEmpty(value: string, field: string): void {
  if (value.trim() === "") {
    throw new Error(`AMENDMENT_${field.toUpperCase()}_EMPTY`);
  }
}

type ConstitutionalAmendmentUnsignedProposal = Omit<
  ConstitutionalAmendmentProposal,
  "approval" | "governanceAuthorityCertificate"
>;

function proposalSigningPayload(
  proposal: ConstitutionalAmendmentUnsignedProposal,
): string {
  return canonicalize(proposal);
}

export function createHumanApprovalKeyPair(): {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
} {
  return generateKeyPairSync("ed25519");
}

export function signHumanApproval(
  proposal: ConstitutionalAmendmentUnsignedProposal,
  approverId: string,
  authorityId: string,
  privateKey: KeyObject,
  publicKeyPem: string,
  approvedAt = new Date().toISOString(),
  keyId = "constitutional-approval-key",
): ConstitutionalHumanApproval {
  assertNonEmpty(approverId, "approver_id");
  assertNonEmpty(authorityId, "authority_id");
  assertNonEmpty(publicKeyPem, "public_key");
  assertNonEmpty(approvedAt, "approved_at");
  assertNonEmpty(keyId, "key_id");

  const fingerprint = publicKeyFingerprint(publicKeyPem);

  const approvalPayload = canonicalize({
    proposal,
    approval: {
      approverId,
      authorityId,
      approvedAt,
      signatureAlgorithm: "Ed25519",
      keyId,
      publicKeyPem,
      publicKeyFingerprint: fingerprint,
    },
  });

  const signature = sign(
    null,
    Buffer.from(approvalPayload, "utf8"),
    privateKey,
  );

  return Object.freeze({
    approverId,
    authorityId,
    approvedAt,
    signatureAlgorithm: "Ed25519",
    keyId,
    publicKeyPem,
    publicKeyFingerprint: fingerprint,
    signatureBase64: signature.toString("base64"),
  });
}

function verifyHumanApproval(
  proposal: ConstitutionalAmendmentProposal,
): boolean {
  const approval = proposal.approval;

  if (
    approval.signatureAlgorithm !== "Ed25519" ||
    approval.approverId.trim() === "" ||
    approval.authorityId.trim() === "" ||
    approval.approvedAt.trim() === "" ||
    approval.keyId.trim() === "" ||
    approval.publicKeyPem.trim() === "" ||
    approval.publicKeyFingerprint.trim() === "" ||
    approval.signatureBase64.trim() === ""
  ) {
    return false;
  }

  if (
    approval.publicKeyFingerprint !==
    publicKeyFingerprint(approval.publicKeyPem)
  ) {
    return false;
  }

  try {
    const publicKey = requirePublicKey(approval.publicKeyPem);

    const approvalPayload = canonicalize({
      proposal: {
        amendmentId: proposal.amendmentId,
        baseVersion: proposal.baseVersion,
        proposedVersion: proposal.proposedVersion,
        reason: proposal.reason,
        proposerId: proposal.proposerId,
        proposedAt: proposal.proposedAt,
        baseline: proposal.baseline,
        proposed: proposal.proposed,
          governanceAuthoritySet: proposal.governanceAuthoritySet,
      },
      approval: {
        approverId: approval.approverId,
        authorityId: approval.authorityId,
        approvedAt: approval.approvedAt,
        signatureAlgorithm: approval.signatureAlgorithm,
        keyId: approval.keyId,
        publicKeyPem: approval.publicKeyPem,
        publicKeyFingerprint: approval.publicKeyFingerprint,
      },
    });

    return verify(
      null,
      Buffer.from(approvalPayload, "utf8"),
      publicKey,
      Buffer.from(approval.signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}

function requirePublicKey(publicKeyPem: string): KeyObject {
  return createPublicKey(publicKeyPem);
}

export interface ConstitutionalApprovalContext {
  readonly trustChain: TrustChainInput;
  readonly keyBoundary: KeySecurityBoundary;
  readonly governanceAuthoritySet: GovernanceAuthoritySet;
}

function amendmentGovernancePayload(
  proposal: ConstitutionalAmendmentProposal,
): ConstitutionalAmendmentUnsignedProposal {
  return {
    amendmentId: proposal.amendmentId,
    baseVersion: proposal.baseVersion,
    proposedVersion: proposal.proposedVersion,
    reason: proposal.reason,
    proposerId: proposal.proposerId,
    proposedAt: proposal.proposedAt,
    baseline: proposal.baseline,
    proposed: proposal.proposed,
          governanceAuthoritySet: proposal.governanceAuthoritySet,
  };
}

function validateGovernanceAmendmentAuthority(
  proposal: ConstitutionalAmendmentProposal,
  context?: ConstitutionalApprovalContext,
): NoDowngradeViolation[] {
  const violations: NoDowngradeViolation[] = [];

  if (context === undefined) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Pinned governance authority context is required for constitutional amendment.",
    });
    return violations;
  }

  const trusted = context.governanceAuthoritySet;
  const supplied = proposal.governanceAuthoritySet;

    if (canonicalize(supplied) !== canonicalize(trusted)) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Constitutional amendment governance authority set does not match the pinned trust root.",
    });
    return violations;
  }

  const certificateResult = verifyGovernanceAuthorityCertificate(
    amendmentGovernancePayload(proposal),
    proposal.governanceAuthorityCertificate,
    trusted,
  );

  if (!certificateResult.valid) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message:
        `Constitutional amendment governance authority verification failed: ${certificateResult.reason}`,
    });
  }

  return violations;
}

function validateHumanAmendmentAuthority(
  proposal: ConstitutionalAmendmentProposal,
  identity: Identity,
  authority: Authority,
  context?: ConstitutionalApprovalContext,
): NoDowngradeViolation[] {
  const violations: NoDowngradeViolation[] = [];

  if (identity.kind !== "human") {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Constitutional amendment approval requires a human identity.",
    });
  }

  if (!isUsableIdentity(identity)) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Approver identity is not usable.",
    });
  }

  if (!isUsableAuthority(authority, proposal.approval.approvedAt)) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Amendment authority is not usable at approval time.",
    });
  }

  if (proposal.approval.approverId !== identity.id) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Approval approver identity does not match authenticated identity.",
    });
  }

  if (proposal.approval.authorityId !== authority.id) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Approval authority does not match supplied authority.",
    });
  }

  if (authority.holderIdentityId !== identity.id) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Amendment authority is not held by the authenticated human.",
    });
  }

  if (!authority.scope.includes("constitutional:amendment")) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Authority lacks constitutional amendment scope.",
    });
  }

  if (context === undefined) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Cryptographically bound trust and key context is required.",
    });

    return violations;
  }

  const chain = context.trustChain;
  const trustResult = verifyTrustChain(chain);

  if (!trustResult.valid) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message:
        `Constitutional approval trust chain invalid: ${trustResult.reason}`,
    });
  }

  if (chain.credential.subject !== identity.id) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Approval credential is not bound to the authenticated human.",
    });
  }

  if (authority.trustCredentialId !== chain.credential.id) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Authority trust credential does not match approval credential.",
    });
  }

  const approval = proposal.approval;

  let registeredKey: TrustKey | null = null;

  try {
    registeredKey = context.keyBoundary.getPublicKey(approval.keyId);
  } catch {
    registeredKey = null;
  }

  if (registeredKey === null) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Approval key is not registered in the security boundary.",
    });
  } else {
    if (registeredKey.publicKeyPem !== approval.publicKeyPem) {
      violations.push({
        code: "AMBIGUOUS_COMPARISON",
        invariantId: proposal.amendmentId,
        message: "Approval public key does not match registered key.",
      });
    }

    if (registeredKey.status !== "active") {
      violations.push({
        code: "AMBIGUOUS_COMPARISON",
        invariantId: proposal.amendmentId,
        message: "Approval key is not active.",
      });
    }

    if (registeredKey.purpose !== "execution") {
      violations.push({
        code: "AMBIGUOUS_COMPARISON",
        invariantId: proposal.amendmentId,
        message:
          "Constitutional approval key has an unauthorized key purpose.",
      });
    }

    if (
      approval.approvedAt < registeredKey.notBefore ||
      (registeredKey.notAfter !== undefined &&
        approval.approvedAt >= registeredKey.notAfter)
    ) {
      violations.push({
        code: "AMBIGUOUS_COMPARISON",
        invariantId: proposal.amendmentId,
        message: "Approval key is outside its validity interval.",
      });
    }

    if (
      !context.keyBoundary.verifyKeyState(
        approval.keyId,
        proposal.approval.approvedAt,
        approval.publicKeyPem,
      )
    ) {
      violations.push({
        code: "AMBIGUOUS_COMPARISON",
        invariantId: proposal.amendmentId,
        message:
          "Registered approval key is not usable or is not bound to the approved public key.",
      });
    }
  }

  const claims = chain.credential.claims;

  if (
    claims["giia.constitutional.approval.identityId"] !==
    identity.id
  ) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Credential does not bind the constitutional approval identity.",
    });
  }

  if (
    claims["giia.constitutional.approval.authorityId"] !==
    authority.id
  ) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Credential does not bind the constitutional approval authority.",
    });
  }

  if (
    claims["giia.constitutional.approval.keyId"] !==
    approval.keyId
  ) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Credential does not bind the constitutional approval key.",
    });
  }

  if (
    claims["giia.constitutional.approval.publicKeyFingerprint"] !==
    approval.publicKeyFingerprint
  ) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message:
        "Credential does not bind the constitutional approval public key.",
    });
  }

  const authorization = authorize(
    {
      id: `constitutional-amendment-${proposal.amendmentId}`,
      subjectIdentityId: identity.id,
      authorityId: authority.id,
      action: "constitutional",
      resource: "amendment",
      requestedAt: proposal.approval.approvedAt,
    },
    identity,
    authority,
  );

  if (
    authorization.decision !== "ALLOW" ||
    authorization.authoritative !== false
  ) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message:
        `Constitutional amendment authorization failed: ${authorization.reason}`,
    });
  }

  return violations;
}

function validateProposal(
  proposal: ConstitutionalAmendmentProposal,
  identity?: Identity,
  authority?: Authority,
  context?: ConstitutionalApprovalContext,
): NoDowngradeViolation[] {
  const violations: NoDowngradeViolation[] = [];

  for (const [value, field] of [
    [proposal.amendmentId, "amendment_id"],
    [proposal.baseVersion, "base_version"],
    [proposal.proposedVersion, "proposed_version"],
    [proposal.reason, "reason"],
    [proposal.proposerId, "proposer_id"],
    [proposal.proposedAt, "proposed_at"],
  ] as const) {
    if (value.trim() === "") {
      violations.push({
        code: "VERSION_INVALID",
        invariantId: field,
        message: `${field} must be non-empty.`,
      });
    }
  }

  if (proposal.baseline.length === 0 || proposal.proposed.length === 0) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Both baseline and proposed constitutional registries are required.",
    });
  }

  if (!verifyHumanApproval(proposal)) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Valid cryptographic human approval is required.",
    });
  }

  violations.push(
    ...validateGovernanceAmendmentAuthority(proposal, context),
  );

  if (identity === undefined || authority === undefined) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Authenticated human identity and amendment authority are required.",
    });
  } else {
    violations.push(
      ...validateHumanAmendmentAuthority(
        proposal,
        identity,
        authority,
        context,
      ),
    );
  }

  return violations;
}

export function evaluateConstitutionalAmendment(
  proposal: ConstitutionalAmendmentProposal,
  identity?: Identity,
  authority?: Authority,
  context?: ConstitutionalApprovalContext,
  committedAt = new Date().toISOString(),
): ConstitutionalAmendmentResult {
  const violations = validateProposal(
    proposal,
    identity,
    authority,
    context,
  );

  if (committedAmendments.has(proposal.amendmentId)) {
    violations.push({
      code: "AMBIGUOUS_COMPARISON",
      invariantId: proposal.amendmentId,
      message: "Amendment has already been committed.",
    });
  }

  if (violations.length === 0) {
    violations.push(
      ...compareConstitutionalVersions(
        proposal.baseline,
        proposal.proposed,
      ).violations,
    );
  }

  if (violations.length > 0) {
    return Object.freeze({
      allowed: false,
      decision: "DENIED",
      violations: Object.freeze(violations),
      evidence: null,
    });
  }

  const approvalHash = sha256(proposal.approval);
  const proposalHash = sha256({
    amendmentId: proposal.amendmentId,
    baseVersion: proposal.baseVersion,
    proposedVersion: proposal.proposedVersion,
    reason: proposal.reason,
    proposerId: proposal.proposerId,
    proposedAt: proposal.proposedAt,
    baseline: proposal.baseline,
    proposed: proposal.proposed,
  });

  const previousEvidenceHash =
    amendmentLedger.length === 0
      ? null
      : amendmentLedger[amendmentLedger.length - 1]!.evidenceHash;

  const evidenceBody = {
    amendmentId: proposal.amendmentId,
    baseVersion: proposal.baseVersion,
    proposedVersion: proposal.proposedVersion,
    proposalHash,
    approvalHash,
    decision: "APPROVED" as const,
    committedAt,
    previousEvidenceHash,
  };

  const evidence: ConstitutionalAmendmentEvidence = Object.freeze({
    evidenceId: `AMENDMENT-EVIDENCE-${proposal.amendmentId}`,
    ...evidenceBody,
    evidenceHash: sha256(evidenceBody),
  });

  amendmentLedger.push(evidence);
  committedAmendments.add(proposal.amendmentId);

  return Object.freeze({
    allowed: true,
    decision: "APPROVED",
    violations: Object.freeze([]),
    evidence,
  });
}

export function listConstitutionalAmendmentEvidence(): readonly ConstitutionalAmendmentEvidence[] {
  return Object.freeze([...amendmentLedger]);
}

export function verifyConstitutionalAmendmentEvidenceChain(): boolean {
  let previous: string | null = null;

  for (const evidence of amendmentLedger) {
    if (evidence.previousEvidenceHash !== previous) {
      return false;
    }

    const body = {
      amendmentId: evidence.amendmentId,
      baseVersion: evidence.baseVersion,
      proposedVersion: evidence.proposedVersion,
      proposalHash: evidence.proposalHash,
      approvalHash: evidence.approvalHash,
      decision: evidence.decision,
      committedAt: evidence.committedAt,
      previousEvidenceHash: evidence.previousEvidenceHash,
    };

    if (sha256(body) !== evidence.evidenceHash) {
      return false;
    }

    previous = evidence.evidenceHash;
  }

  return true;
}
