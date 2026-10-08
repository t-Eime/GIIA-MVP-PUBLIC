import type { GovernancePipelineResult } from "../trust-action/pipeline-types.js";
import type { GovernorResult } from "../governor/types.js";
import type { GuardianResult } from "../guardian/types.js";

export interface OrganPipelineProjection {
  readonly requestId: string;
  readonly actorId: string;
  readonly action: string;
  readonly target: string;

  /**
   * The authoritative pipeline decision.
   * Organ decisions may never contradict this into an ALLOW.
   */
  readonly pipelineDecision: GovernancePipelineResult["decision"]["decision"];

  readonly pipelineProvenance: string;

  readonly authorityVerified: boolean;
  readonly delegationVerified: boolean;
  readonly jurisdictionVerified: boolean;
  readonly policyVerified: boolean;
  readonly constitutionVerified: boolean;
  readonly prohibited: boolean;

  readonly harmRisk: GovernancePipelineResult["harmRisk"]["classification"];
  readonly harmRiskAssessed: boolean;

  readonly evidenceIntegrityVerified: boolean;
  readonly evidenceCommitted: boolean;
  readonly auditIntegrityVerified: boolean;
  readonly auditCommitted: boolean;

  readonly assuranceSatisfied: boolean;
  readonly authorizationDecision: GovernancePipelineResult["authorization"]["decision"];

  readonly exactActionBound: boolean;
  readonly executionPermitted: false;
}

export interface IntegratedOrganAssessment {
  readonly governor: GovernorResult;
  readonly guardian: GuardianResult;
  readonly projection: OrganPipelineProjection;
}

