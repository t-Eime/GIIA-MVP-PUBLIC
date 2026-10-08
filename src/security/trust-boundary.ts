import { invariant } from "../core/errors.js";
import { canonicalize } from "../core/canonical.js";
import { sha256 } from "../core/security.js";
import {
  verifyAuthenticatedVerificationEvidence,
  type AuthenticatedVerificationEvidence,
} from "../trust/verification.js";

export type TrustCheck =
  | "IDENTITY"
  | "AUTHENTICITY"
  | "INTEGRITY"
  | "PROVENANCE"
  | "AUTHORITY"
  | "AUTHORIZATION"
  | "VERIFICATION";

export type TrustDisposition =
  | "TRUSTED"
  | "RESTRICTED"
  | "ISOLATED"
  | "QUARANTINED"
  | "REVOKED";

export interface TrustCheckEvidence {
  check: TrustCheck;
  subjectId: string;
  verifiedAt: string;
  evidenceRef: string;
  evidenceHash: string;
  authenticatedVerification?: AuthenticatedVerificationEvidence;
}

export interface TrustAssessmentInput {
  subjectId: string;
  evidence: Partial<Record<TrustCheck, TrustCheckEvidence>>;
  previouslyTrusted?: boolean;
  assessedAt: string;
}

export interface TrustAssessment {
  subjectId: string;
  trusted: boolean;
  disposition: TrustDisposition;
  consequentialAuthorityAllowed: boolean;
  failedChecks: TrustCheck[];
  reason: string;
}

const REQUIRED_CHECKS: readonly TrustCheck[] = [
  "IDENTITY",
  "AUTHENTICITY",
  "INTEGRITY",
  "PROVENANCE",
  "AUTHORITY",
  "AUTHORIZATION",
  "VERIFICATION",
];

function evidencePayload(
  evidence: Omit<TrustCheckEvidence, "evidenceHash">,
): Omit<TrustCheckEvidence, "evidenceHash"> {
  return evidence;
}

function verifyCheckEvidence(
  subjectId: string,
  assessedAt: string,
  check: TrustCheck,
  evidence: TrustCheckEvidence | undefined,
): boolean {
  if (!evidence) return false;

  if (evidence.check !== check) return false;
  if (evidence.subjectId !== subjectId) return false;
  if (evidence.verifiedAt !== assessedAt) return false;
  if (evidence.evidenceRef.trim().length === 0) return false;
  if (evidence.evidenceHash.trim().length === 0) return false;

  const unsigned: Omit<TrustCheckEvidence, "evidenceHash"> = {
    check: evidence.check,
    subjectId: evidence.subjectId,
    verifiedAt: evidence.verifiedAt,
    evidenceRef: evidence.evidenceRef,
    ...(evidence.authenticatedVerification
      ? { authenticatedVerification: evidence.authenticatedVerification }
      : {}),
  };

  if (
    sha256(canonicalize(evidencePayload(unsigned))) !==
    evidence.evidenceHash
  ) {
    return false;
  }

  if (check === "VERIFICATION") {
    if (!evidence.authenticatedVerification) return false;

    return verifyAuthenticatedVerificationEvidence(
      evidence.authenticatedVerification,
      subjectId,
      assessedAt,
    );
  }

  return false;
}

export function createVerificationCheckEvidence(
  authenticatedVerification: AuthenticatedVerificationEvidence,
): TrustCheckEvidence {
  const unsigned: Omit<TrustCheckEvidence, "evidenceHash"> = {
    check: "VERIFICATION",
    subjectId: authenticatedVerification.subjectId,
    verifiedAt: authenticatedVerification.verifiedAt,
    evidenceRef: authenticatedVerification.id,
    authenticatedVerification,
  };

  return {
    ...unsigned,
    evidenceHash: sha256(canonicalize(evidencePayload(unsigned))),
  };
}

export function assessTrustBoundary(
  input: TrustAssessmentInput,
): TrustAssessment {
  invariant(
    input.subjectId.trim().length > 0,
    "TRUST_BOUNDARY_SUBJECT_EMPTY",
    "Trust-boundary subject id is required",
  );

  invariant(
    input.assessedAt.trim().length > 0,
    "TRUST_BOUNDARY_TIME_EMPTY",
    "Trust-boundary assessment time is required",
  );

  const failedChecks = REQUIRED_CHECKS.filter(
    (check) =>
      !verifyCheckEvidence(
        input.subjectId,
        input.assessedAt,
        check,
        input.evidence[check],
      ),
  );

  if (failedChecks.length === 0) {
    return {
      subjectId: input.subjectId,
      trusted: true,
      disposition: "TRUSTED",
      consequentialAuthorityAllowed: true,
      failedChecks: [],
      reason: "ALL_REQUIRED_TRUST_CHECKS_PASSED",
    };
  }

  return {
    subjectId: input.subjectId,
    trusted: false,
    disposition: input.previouslyTrusted
      ? "QUARANTINED"
      : "ISOLATED",
    consequentialAuthorityAllowed: false,
    failedChecks,
    reason: input.previouslyTrusted
      ? "PREVIOUSLY_TRUSTED_SUBJECT_FAILED_TRUST_VERIFICATION"
      : "TRUST_VERIFICATION_INCOMPLETE_OR_FAILED",
  };
}

export function assertConsequentialAuthority(
  assessment: TrustAssessment,
): void {
  invariant(
    assessment.trusted &&
      assessment.consequentialAuthorityAllowed,
    "TRUST_BOUNDARY_AUTHORITY_DENIED",
    `Consequential authority denied for ${assessment.subjectId}: ${assessment.reason}`,
  );
}
