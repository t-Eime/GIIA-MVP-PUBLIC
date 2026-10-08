import type { MvpDecisionRecord } from "../mvp/types.js";
import { validateDecisionRecord } from "../mvp/validation.js";
import {
  verifyDecisionRecordSignature,
} from "../mvp/decision-record.js";
import {
  governanceAuthoritySetFingerprint,
  verifyGovernanceAuthorityCertificate,
  type GovernanceAuthoritySet,
} from "../security/governance-authority.js";
import type {
  GovernanceDecisionReference,
} from "./external-boundary.js";

export interface MvpEnforcementState {
  readonly humanApprovalRequired: boolean;
  readonly humanApprovalVerified: boolean;
  readonly revocationState: "active" | "revoked";
  readonly shutdownState: "clear" | "active";
}

/**
 * The enforcement boundary owns this trust root.
 *
 * The authority set embedded in an MvpDecisionRecord is treated as
 * evidence/provenance only. It is never allowed to establish the
 * enforcement trust root.
 */
export interface MvpEnforcementTrustRoot {
  readonly authoritySet: GovernanceAuthoritySet;
  readonly authoritySetFingerprint: string;
}

/**
 * Creates an independent enforcement bridge with a pinned governance
 * authority trust root.
 *
 * The trusted authority set is captured when the executor/bridge is
 * constructed and is not supplied by an individual decision request.
 */
export function createMvpEnforcementBridge(
  trustedAuthoritySet: GovernanceAuthoritySet,
): {
  readonly project: (
    record: MvpDecisionRecord,
    state: MvpEnforcementState,
  ) => GovernanceDecisionReference;
  readonly trustRoot: MvpEnforcementTrustRoot;
} {
  const authoritySetFingerprint =
    governanceAuthoritySetFingerprint({
      setId: trustedAuthoritySet.setId,
      version: trustedAuthoritySet.version,
      quorum: trustedAuthoritySet.quorum,
      memberCount: trustedAuthoritySet.memberCount,
      members: trustedAuthoritySet.members,
    });

  if (authoritySetFingerprint !== trustedAuthoritySet.fingerprint) {
    throw new Error(
      "MVP_ENFORCEMENT_TRUST_ROOT_INVALID",
    );
  }

  const pinnedAuthoritySet: GovernanceAuthoritySet =
    Object.freeze({
      ...trustedAuthoritySet,
      members: Object.freeze([
        ...trustedAuthoritySet.members,
      ]),
    });

  const trustRoot: MvpEnforcementTrustRoot = Object.freeze({
    authoritySet: pinnedAuthoritySet,
    authoritySetFingerprint,
  });

  function project(
    record: MvpDecisionRecord,
    state: MvpEnforcementState,
  ): GovernanceDecisionReference {
    const validated = validateDecisionRecord(record);

    /*
     * P0-C: independently verify the certificate against the
     * executor-owned trust root, NOT the authority set supplied
     * by the decision record.
     */
    const authorityVerification =
      verifyGovernanceAuthorityCertificate(
        validatedWithoutCertificateForVerification(validated),
        validated.governanceAuthorityCertificate,
        pinnedAuthoritySet,
      );

    if (!authorityVerification.valid) {
      throw new Error(
        `MVP_GOVERNANCE_AUTHORITY_TRUST_ROOT_INVALID:${authorityVerification.reason}`,
      );
    }

    /*
     * The embedded authority set must exactly correspond to the
     * executor's pinned authority set. It remains useful evidence,
     * but cannot redefine trust.
     */
    if (
      validated.governanceAuthoritySet.fingerprint !==
      authoritySetFingerprint
    ) {
      throw new Error(
        "MVP_GOVERNANCE_AUTHORITY_SET_NOT_PINNED",
      );
    }

    if (
      governanceAuthoritySetFingerprint({
        setId: validated.governanceAuthoritySet.setId,
        version: validated.governanceAuthoritySet.version,
        quorum: validated.governanceAuthoritySet.quorum,
        memberCount:
          validated.governanceAuthoritySet.memberCount,
        members: validated.governanceAuthoritySet.members,
      }) !== authoritySetFingerprint
    ) {
      throw new Error(
        "MVP_GOVERNANCE_AUTHORITY_SET_NOT_PINNED",
      );
    }

    /*
     * Preserve the existing full decision-record verification.
     * P0-C adds an independent trust-root check rather than
     * replacing existing validation.
     */
    if (!verifyDecisionRecordSignature(validated)) {
      throw new Error("MVP_DECISION_SIGNATURE_INVALID");
    }

    if (validated.decision !== "ALLOW") {
      throw new Error("MVP_DECISION_NOT_ALLOW");
    }

    if (validated.authoritative !== true) {
      throw new Error("MVP_DECISION_NOT_AUTHORITATIVE");
    }

    if (validated.executionPermitted !== false) {
      throw new Error("MVP_EXECUTION_AUTHORITY_FORBIDDEN");
    }

    if (state.revocationState !== "active") {
      throw new Error("MVP_DECISION_REVOKED");
    }

    return {
      decisionId: validated.decisionId,
      requestId: validated.requestId,
      decision: "ALLOW",
      authoritative: true,
      actorId: validated.executionBinding.actorId,
      action: validated.action,
      target: validated.executionBinding.target,
      payloadHash: validated.executionBinding.payloadHash,
      constitutionVersion:
        validated.executionBinding.constitutionVersion,
      issuedAt: validated.issuedAt,
      expiresAt: validated.executionBinding.expiresAt,
      nonce: validated.executionBinding.nonce,
      humanApprovalRequired:
        state.humanApprovalRequired,
      humanApprovalVerified:
        state.humanApprovalVerified,
      revocationState:
        state.revocationState,
      shutdownState:
        state.shutdownState,
    };
  }

  return Object.freeze({
    project,
    trustRoot,
  });
}

/**
 * Remove only the authority set from the certificate decision
 * material because the certificate itself is defined over the
 * decision material, not over the trust root.
 */
function validatedWithoutCertificateForVerification(
  record: MvpDecisionRecord,
): Omit<MvpDecisionRecord, "signature" | "governanceAuthorityCertificate"> {
  const {
    signature: _signature,
    governanceAuthorityCertificate: _certificate,
    ...decisionMaterial
  } = record;

  return decisionMaterial;
}

/**
 * Compatibility wrapper retained for existing callers.
 *
 * New enforcement code MUST construct a pinned bridge with
 * createMvpEnforcementBridge().
 */
export function projectMvpDecisionForEnforcement(
  record: MvpDecisionRecord,
  state: MvpEnforcementState,
  trustedAuthoritySet?: GovernanceAuthoritySet,
): GovernanceDecisionReference {
  if (!trustedAuthoritySet) {
    throw new Error(
      "MVP_ENFORCEMENT_TRUST_ROOT_REQUIRED",
    );
  }

  return createMvpEnforcementBridge(
    trustedAuthoritySet,
  ).project(record, state);
}
