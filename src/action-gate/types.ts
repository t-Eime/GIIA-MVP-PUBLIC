import type { GovernorResult } from "../governor/types.js";
import type { GuardianResult } from "../guardian/types.js";
import type { InstitutionalIntegrityResult } from "../attestation/types.js";

export interface ActionGateInput {
  readonly governor: GovernorResult;
  readonly guardian: GuardianResult;
  readonly governorIntegrity: InstitutionalIntegrityResult;
  readonly guardianIntegrity: InstitutionalIntegrityResult;
  readonly evidenceValid: boolean;
  readonly authorityValid: boolean;
  readonly constitutionAllows: boolean;
  readonly conditionsValid: boolean;
  readonly noUnresolvedConflict: boolean;
  readonly enforcementHealthy: boolean;
  readonly exactActionBound: boolean;
  readonly actionNotAlreadyExecuted: boolean;
  readonly criticalTrustRootsHealthy: boolean;
}

export type ActionGateDecision = "ALLOW_EXECUTION" | "BLOCK";

export interface ActionGateResult {
  readonly decision: ActionGateDecision;
  readonly reason: string;
  readonly executable: false | true;
  readonly governorDecision: GovernorResult["decision"];
  readonly guardianDecision: GuardianResult["decision"];
}
