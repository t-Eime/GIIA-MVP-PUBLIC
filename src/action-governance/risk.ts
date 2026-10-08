import type {
  ActionClass,
  HarmRiskLevel,
} from "../trust-action/pipeline-types.js";
import type {
  HarmRiskResult,
  HarmRiskRule,
} from "./types.js";

export const HARM_RISK_VERSION = "harm-risk-v1";

export const HARM_RISK_RULES: readonly HarmRiskRule[] = [
  {
    id: "hr-v1-read",
    version: HARM_RISK_VERSION,
    actionClass: "READ",
    risk: "LOW",
    provenance: "giia-governed-harm-risk-v1",
  },
  {
    id: "hr-v1-write",
    version: HARM_RISK_VERSION,
    actionClass: "WRITE",
    risk: "MODERATE",
    provenance: "giia-governed-harm-risk-v1",
  },
  {
    id: "hr-v1-execute",
    version: HARM_RISK_VERSION,
    actionClass: "EXECUTE",
    risk: "HIGH",
    provenance: "giia-governed-harm-risk-v1",
  },
  {
    id: "hr-v1-administrative",
    version: HARM_RISK_VERSION,
    actionClass: "ADMINISTRATIVE",
    risk: "HIGH",
    provenance: "giia-governed-harm-risk-v1",
  },
  {
    id: "hr-v1-consequential",
    version: HARM_RISK_VERSION,
    actionClass: "CONSEQUENTIAL",
    risk: "CRITICAL",
    provenance: "giia-governed-harm-risk-v1",
  },
];

export function assessHarmRisk(
  action: string,
  resource: string,
  actionClass: ActionClass | null,
  rules: readonly HarmRiskRule[] = HARM_RISK_RULES,
): HarmRiskResult {
  if (!actionClass) {
    return {
      action,
      resource,
      actionClass: null,
      classification: "UNKNOWN",
      ruleId: null,
      ruleVersion: null,
      assessed: false,
      basis: "ACTION_CLASS_UNAVAILABLE",
      provenance: "giia-harm-risk-assessor",
    };
  }

  const rule = rules.find(
    (candidate) => candidate.actionClass === actionClass,
  );

  if (!rule) {
    return {
      action,
      resource,
      actionClass,
      classification: "UNKNOWN",
      ruleId: null,
      ruleVersion: null,
      assessed: false,
      basis: "HARM_RISK_RULE_UNAVAILABLE",
      provenance: "giia-harm-risk-assessor",
    };
  }

  return {
    action,
    resource,
    actionClass,
    classification: rule.risk,
    ruleId: rule.id,
    ruleVersion: rule.version,
    assessed: true,
    basis: `ACTION_CLASS_BASELINE:${actionClass}`,
    provenance: rule.provenance,
  };
}
