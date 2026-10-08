import { invariant } from "../core/errors.js";
import {
  validateNonEmpty,
  validateTimestamp,
} from "../core/validation.js";
import type {
  GovernanceRequest,
  GovernanceResult,
  GovernanceRule,
} from "./types.js";
import { verifyGovernanceRule } from "./crypto.js";
import { verifyTrustChain } from "../trust/service.js";
import type {
  TrustCredential,
  TrustKey,
  TrustRoot,
  TrustAnchor,
  TrustDelegation,
} from "../trust/types.js";

export function validateGovernanceRule(rule: GovernanceRule): void {
  validateNonEmpty(rule.id, "GOVERNANCE_ID_EMPTY", "Governance rule id is required");
  validateNonEmpty(rule.version, "GOVERNANCE_VERSION_EMPTY", "Governance version is required");
  validateNonEmpty(rule.name, "GOVERNANCE_NAME_EMPTY", "Governance rule name is required");
  validateNonEmpty(rule.issuer, "GOVERNANCE_ISSUER_EMPTY", "Governance issuer is required");
  validateNonEmpty(rule.provenance, "GOVERNANCE_PROVENANCE_EMPTY", "Governance provenance is required");

  if (rule.jurisdiction !== undefined) {
    validateNonEmpty(
      rule.jurisdiction,
      "GOVERNANCE_JURISDICTION_EMPTY",
      "Governance jurisdiction cannot be empty",
    );
  }

  validateTimestamp(
    rule.effectiveFrom,
    "GOVERNANCE_EFFECTIVE_FROM_INVALID",
    "Governance effectiveFrom must be a valid timestamp",
  );

  if (rule.effectiveUntil !== undefined) {
    validateTimestamp(
      rule.effectiveUntil,
      "GOVERNANCE_EFFECTIVE_UNTIL_INVALID",
      "Governance effectiveUntil must be a valid timestamp",
    );

    invariant(
      rule.effectiveUntil > rule.effectiveFrom,
      "GOVERNANCE_EFFECTIVE_WINDOW_INVALID",
      "Governance effectiveUntil must be after effectiveFrom",
    );
  }

  invariant(
    rule.appliesToActions.length > 0,
    "GOVERNANCE_ACTIONS_EMPTY",
    "Governance rule must apply to at least one action",
  );

  for (const action of rule.appliesToActions) {
    validateNonEmpty(
      action,
      "GOVERNANCE_ACTION_EMPTY",
      "Governance action cannot be empty",
    );
  }
}

export interface GovernanceAuthorityVerificationInput {
  root: TrustRoot;
  rootKey: TrustKey;
  anchor: TrustAnchor;
  anchorKey: TrustKey;
  delegation: TrustDelegation;
  delegationKey: TrustKey;
  credential: TrustCredential;
  at: string;
}

export function isGovernanceRuleAuthorized(
  rule: GovernanceRule,
  trust: GovernanceAuthorityVerificationInput,
): boolean {
  validateGovernanceRule(rule);

  if (!rule.signature) return false;

  const chain = verifyTrustChain({
    root: trust.root,
    rootKey: trust.rootKey,
    anchor: trust.anchor,
    anchorKey: trust.anchorKey,
    delegation: trust.delegation,
    delegationKey: trust.delegationKey,
    credential: trust.credential,
    at: trust.at,
  });

  if (!chain.valid) return false;

  if (trust.credential.subject !== rule.issuer) return false;

  if (trust.credential.claims["governance:policy"] !== "true") {
    return false;
  }

  return verifyGovernanceRule(
    rule,
    trust.delegationKey.publicKeyPem,
  );
}

export function isGovernanceRuleApplicable(
  rule: GovernanceRule,
  request: GovernanceRequest,
): boolean {
  return (
    rule.status === "active" &&
    request.requestedAt >= rule.effectiveFrom &&
    (rule.effectiveUntil === undefined ||
      request.requestedAt < rule.effectiveUntil) &&
    rule.appliesToActions.includes(request.action) &&
    (rule.jurisdiction === undefined ||
      rule.jurisdiction === request.jurisdiction)
  );
}

export function evaluateGovernance(
  request: GovernanceRequest,
  rules: GovernanceRule[],
): GovernanceResult {
  for (const rule of rules) {
    validateGovernanceRule(rule);
  }

  const applicable = rules
    .filter((r) => isGovernanceRuleApplicable(r, request))
    .sort((a, b) => {
      if (b.precedence !== a.precedence) {
        return b.precedence - a.precedence;
      }
      return a.id.localeCompare(b.id);
    });

  if (applicable.length === 0) {
    return {
      requestId: request.id,
      decision: "DEFER",
      reason: "NO_APPLICABLE_GOVERNANCE_RULE",
    authoritative: false,
      ruleIds: [],
      governanceVersion: "unknown",
    };
  }

  const prohibited = applicable.find((r) =>
    r.prohibitedActions.includes(request.action),
  );

  if (prohibited) {
    return {
      requestId: request.id,
      decision: "DENY",
      reason: "ACTION_PROHIBITED",
    authoritative: false,
      ruleIds: [prohibited.id],
      governanceVersion: prohibited.version,
    };
  }

  const missing = applicable.find((r) =>
    r.requiredConditions.some(
      (condition) => !request.satisfiedConditions.includes(condition),
    ),
  );

  if (missing) {
    return {
      requestId: request.id,
      decision: "DEFER",
      reason: "REQUIRED_CONDITION_UNSATISFIED",
    authoritative: false,
      ruleIds: [missing.id],
      governanceVersion: missing.version,
    };
  }

  return {
    requestId: request.id,
    decision: "ALLOW",
    reason: "GOVERNANCE_ALLOWED",
    authoritative: false,
    ruleIds: applicable.map((r) => r.id),
    governanceVersion: applicable[0]!.version,
  };
}
