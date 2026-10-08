export type GuardianDecision = "ALLOW" | "DENY" | "DEFER" | "CONTAIN";

export interface GuardianInput {
  readonly requestId: string;
  readonly actorId: string;
  readonly action: string;
  readonly target: string;
  readonly harmAcceptable: boolean;
  readonly integrityConditionsValid: boolean;
  readonly emergencyValid: boolean;
  readonly resourceConditionsValid: boolean;
  readonly anomalyResolved: boolean;
  readonly evidenceValid: boolean;
  readonly at: string;
}

export interface GuardianAssessment {
  readonly organ: "GUARDIAN";
  readonly decision: GuardianDecision;
  readonly reason: string;
  readonly requestId: string;
  readonly actorId: string;
  readonly action: string;
  readonly target: string;
  readonly issuedAt: string;
  readonly authoritative: false;
  readonly source: "ORGAN_ASSESSMENT";
}

export interface GuardianResult {
  readonly organ: "GUARDIAN";
  readonly decision: GuardianDecision;
  readonly reason: string;
  readonly requestId: string;
  readonly actorId: string;
  readonly action: string;
  readonly target: string;
  readonly issuedAt: string;
  readonly authoritative: true;
  readonly source: "AUTHORITATIVE_GIIA_PIPELINE";
}
