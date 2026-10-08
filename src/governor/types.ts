export type GovernorDecision = "ALLOW" | "DENY" | "DEFER";

export interface GovernorInput {
  readonly requestId: string;
  readonly actorId: string;
  readonly action: string;
  readonly target: string;
  readonly authorityValid: boolean;
  readonly delegationValid: boolean;
  readonly jurisdictionValid: boolean;
  readonly policyAllows: boolean;
  readonly constitutionAllows: boolean;
  readonly prohibited: boolean;
  readonly evidenceValid: boolean;
  readonly at: string;
}

export interface GovernorAssessment {
  readonly organ: "GOVERNOR";
  readonly decision: GovernorDecision;
  readonly reason: string;
  readonly requestId: string;
  readonly actorId: string;
  readonly action: string;
  readonly target: string;
  readonly issuedAt: string;
  readonly authoritative: false;
  readonly source: "ORGAN_ASSESSMENT";
}

export interface GovernorResult {
  readonly organ: "GOVERNOR";
  readonly decision: GovernorDecision;
  readonly reason: string;
  readonly requestId: string;
  readonly actorId: string;
  readonly action: string;
  readonly target: string;
  readonly issuedAt: string;
  readonly authoritative: true;
  readonly source: "AUTHORITATIVE_GIIA_PIPELINE";
}
