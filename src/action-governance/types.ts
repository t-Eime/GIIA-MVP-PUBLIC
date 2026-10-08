import type {
  ActionClass,
  HarmRiskLevel,
} from "../trust-action/pipeline-types.js";

export interface ActionClassificationRule {
  id: string;
  version: string;
  action: string;
  classification: ActionClass;
  provenance: string;
}

export interface ActionClassificationResult {
  action: string;
  classification: ActionClass | null;
  ruleId: string | null;
  ruleVersion: string | null;
  determined: boolean;
  reason: string;
  provenance: string;
}

export interface HarmRiskRule {
  id: string;
  version: string;
  actionClass: ActionClass;
  risk: Exclude<HarmRiskLevel, "UNKNOWN">;
  provenance: string;
}

export interface HarmRiskResult {
  action: string;
  resource: string;
  actionClass: ActionClass | null;
  classification: HarmRiskLevel;
  ruleId: string | null;
  ruleVersion: string | null;
  assessed: boolean;
  basis: string;
  provenance: string;
}
