import type {
  ActionClassificationResult,
  ActionClassificationRule,
} from "./types.js";

export const ACTION_CLASSIFICATION_VERSION = "action-classification-v1";

export const ACTION_CLASSIFICATION_RULES: readonly ActionClassificationRule[] = [
  {
    id: "ac-v1-read",
    version: ACTION_CLASSIFICATION_VERSION,
    action: "read",
    classification: "READ",
    provenance: "giia-governed-action-classification-v1",
  },
  {
    id: "ac-v1-write",
    version: ACTION_CLASSIFICATION_VERSION,
    action: "write",
    classification: "WRITE",
    provenance: "giia-governed-action-classification-v1",
  },
  {
    id: "ac-v1-delete",
    version: ACTION_CLASSIFICATION_VERSION,
    action: "DELETE",
    classification: "CONSEQUENTIAL",
    provenance: "giia-governed-action-classification-v1",
  },
  {
    id: "ac-v1-restore-online",
    version: ACTION_CLASSIFICATION_VERSION,
    action: "RESTORE_ONLINE",
    classification: "ADMINISTRATIVE",
    provenance: "giia-governed-action-classification-v1",
  },
  {
    id: "ac-v1-enter-degraded",
    version: ACTION_CLASSIFICATION_VERSION,
    action: "ENTER_DEGRADED",
    classification: "ADMINISTRATIVE",
    provenance: "giia-governed-action-classification-v1",
  },
  {
    id: "ac-v1-enter-offline",
    version: ACTION_CLASSIFICATION_VERSION,
    action: "ENTER_OFFLINE",
    classification: "ADMINISTRATIVE",
    provenance: "giia-governed-action-classification-v1",
  },
];

export function classifyAction(
  action: string,
  rules: readonly ActionClassificationRule[] = ACTION_CLASSIFICATION_RULES,
): ActionClassificationResult {
  const normalized = action.trim();

  if (normalized.length === 0) {
    return {
      action,
      classification: null,
      ruleId: null,
      ruleVersion: null,
      determined: false,
      reason: "ACTION_EMPTY",
      provenance: "giia-action-classifier",
    };
  }

  const rule = rules.find((candidate) => candidate.action === normalized);

  if (!rule) {
    return {
      action: normalized,
      classification: null,
      ruleId: null,
      ruleVersion: null,
      determined: false,
      reason: "ACTION_CLASSIFICATION_UNKNOWN",
      provenance: "giia-action-classifier",
    };
  }

  return {
    action: normalized,
    classification: rule.classification,
    ruleId: rule.id,
    ruleVersion: rule.version,
    determined: true,
    reason: "ACTION_CLASSIFIED",
    provenance: rule.provenance,
  };
}
