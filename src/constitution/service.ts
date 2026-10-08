import { invariant } from "../core/errors.js";
import {
  validateNonEmpty,
  validateTimestamp,
} from "../core/validation.js";
import type {
  ConstitutionalRequest,
  ConstitutionalResult,
  ConstitutionalRule,
  GovernanceConflict,
} from "./types.js";
import { verifyConstitutionalRule } from "./crypto.js";
import { verifyTrustChain } from "../trust/service.js";
import type {
  TrustAnchor,
  TrustCredential,
  TrustDelegation,
  TrustKey,
  TrustRoot,
} from "../trust/types.js";

export function validateConstitutionalRule(
  rule: ConstitutionalRule,
): void {
  validateNonEmpty(
    rule.id,
    "CONSTITUTION_RULE_ID_EMPTY",
    "Constitutional rule id is required",
  );

  validateNonEmpty(
    rule.version,
    "CONSTITUTION_RULE_VERSION_EMPTY",
    "Constitutional rule version is required",
  );

  validateNonEmpty(
    rule.name,
    "CONSTITUTION_RULE_NAME_EMPTY",
    "Constitutional rule name is required",
  );

  validateNonEmpty(
    rule.issuer,
    "CONSTITUTION_RULE_ISSUER_EMPTY",
    "Constitutional rule issuer is required",
  );

  validateNonEmpty(
    rule.provenance,
    "CONSTITUTION_RULE_PROVENANCE_EMPTY",
    "Constitutional rule provenance is required",
  );

  validateNonEmpty(
    rule.signature,
    "CONSTITUTION_RULE_SIGNATURE_EMPTY",
    "Constitutional rule signature is required",
  );

  validateTimestamp(
    rule.effectiveFrom,
    "CONSTITUTION_RULE_EFFECTIVE_FROM_INVALID",
    "Constitutional effectiveFrom is invalid",
  );

  if (rule.effectiveUntil !== undefined) {
    validateTimestamp(
      rule.effectiveUntil,
      "CONSTITUTION_RULE_EFFECTIVE_UNTIL_INVALID",
      "Constitutional effectiveUntil is invalid",
    );

    invariant(
      rule.effectiveUntil > rule.effectiveFrom,
      "CONSTITUTION_RULE_WINDOW_INVALID",
      "Constitutional effectiveUntil must be after effectiveFrom",
    );
  }

  invariant(
    Number.isInteger(rule.precedence),
    "CONSTITUTION_RULE_PRECEDENCE_INVALID",
    "Constitutional precedence must be an integer",
  );

  invariant(
    rule.appliesToActions.length > 0,
    "CONSTITUTION_RULE_ACTIONS_EMPTY",
    "Constitutional rule must apply to at least one action",
  );

  for (const action of rule.appliesToActions) {
    validateNonEmpty(
      action,
      "CONSTITUTION_RULE_ACTION_EMPTY",
      "Constitutional action cannot be empty",
    );
  }

  for (const principle of rule.immutablePrinciples) {
    validateNonEmpty(
      principle,
      "CONSTITUTION_RULE_PRINCIPLE_EMPTY",
      "Immutable principles cannot contain empty values",
    );
  }

  invariant(
    rule.status !== "unknown",
    "CONSTITUTION_RULE_STATUS_UNKNOWN",
    "Constitutional rule status cannot be unknown",
  );

  if (rule.scope === "jurisdiction") {
    validateNonEmpty(
      rule.jurisdiction ?? "",
      "CONSTITUTION_JURISDICTION_REQUIRED",
      "Jurisdictional rules require a jurisdiction",
    );
  }
}

function isApplicable(
  rule: ConstitutionalRule,
  request: ConstitutionalRequest,
): boolean {
  if (rule.status !== "active") return false;

  if (request.requestedAt < rule.effectiveFrom) return false;

  if (
    rule.effectiveUntil !== undefined &&
    request.requestedAt >= rule.effectiveUntil
  ) {
    return false;
  }

  if (!rule.appliesToActions.includes(request.action)) {
    return false;
  }

  if (
    rule.scope === "jurisdiction" &&
    rule.jurisdiction !== request.jurisdiction
  ) {
    return false;
  }

  return true;
}

function specificity(rule: ConstitutionalRule): number {
  switch (rule.scope) {
    case "organization":
      return 4;
    case "jurisdiction":
      return 3;
    case "domain":
      return 2;
    case "global":
      return 1;
  }
}

function deniesAction(
  rule: ConstitutionalRule,
  action: string,
): boolean {
  return rule.prohibitedActions.includes(action);
}

function violatesGlobalImmutablePrinciple(
  globalRules: ConstitutionalRule[],
  candidate: ConstitutionalRule,
): boolean {
  if (candidate.scope === "global") return false;

  for (const globalRule of globalRules) {
    for (const principle of globalRule.immutablePrinciples) {
      if (!candidate.immutablePrinciples.includes(principle)) {
        return true;
      }
    }
  }

  return false;
}

export function resolveConstitutionalConflict(
  rules: ConstitutionalRule[],
  action?: string,
): GovernanceConflict | null {
  if (rules.length <= 1) return null;

  const effectiveAction =
    action ??
    (rules.length === 1 ? rules[0]!.appliesToActions[0] : undefined);

  if (effectiveAction === undefined) {
    return {
      ruleIds: rules.map((rule) => rule.id),
      reason: "CONSTITUTIONAL_ACTION_CONTEXT_REQUIRED",
    };
  }

  const highestPrecedence = Math.max(
    ...rules.map((rule) => rule.precedence),
  );

  const precedenceMatches = rules.filter(
    (rule) => rule.precedence === highestPrecedence,
  );

  if (precedenceMatches.length <= 1) return null;

  const highestSpecificity = Math.max(
    ...precedenceMatches.map(specificity),
  );

  const specificityMatches = precedenceMatches.filter(
    (rule) => specificity(rule) === highestSpecificity,
  );

  if (specificityMatches.length <= 1) return null;

  const decisions = specificityMatches.map((rule) => ({
    id: rule.id,
    denies: deniesAction(rule, effectiveAction),
  }));

  const hasMixedPolicy =
    new Set(decisions.map((entry) => entry.denies)).size > 1;

  if (hasMixedPolicy) {
    return {
      ruleIds: specificityMatches.map((rule) => rule.id),
      reason: "CONSTITUTIONAL_POLICY_CONFLICT",
    };
  }

  return null;
}

export interface ConstitutionalAuthorityVerificationInput {
  root: TrustRoot;
  rootKey: TrustKey;
  anchor: TrustAnchor;
  anchorKey: TrustKey;
  delegation: TrustDelegation;
  delegationKey: TrustKey;
  credential: TrustCredential;
  at: string;
}

export function isConstitutionalRuleAuthorized(
  rule: ConstitutionalRule,
  trust: ConstitutionalAuthorityVerificationInput,
): boolean {
  validateConstitutionalRule(rule);

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

  if (trust.credential.claims["governance:constitutional"] !== "true") {
    return false;
  }

  if (
    !verifyConstitutionalRule(
      rule,
      trust.delegationKey.publicKeyPem,
    )
  ) {
    return false;
  }

  return true;
}

export function evaluateConstitution(
  request: ConstitutionalRequest,
  rules: ConstitutionalRule[],
  verifiedRuleIds?: Set<string>,
): ConstitutionalResult {
  for (const rule of rules) {
    validateConstitutionalRule(rule);
  }

  /*
   * Constitutional evaluation is fail-closed.
   *
   * A rule must be explicitly present in verifiedRuleIds.
   * Omitting the verification set means no rule is trusted.
   */
  if (verifiedRuleIds === undefined) {
    return {
      requestId: request.id,
      decision: "DEFER",
      reason: "NO_VERIFIED_CONSTITUTIONAL_RULES",
      ruleIds: [],
      constitutionalVersion: "unknown",
      scope: "none",
      authoritative: false,
    };
  }

  const verifiedRules = rules.filter(
    (rule) => verifiedRuleIds.has(rule.id),
  );

  if (verifiedRules.length === 0) {
    return {
      requestId: request.id,
      decision: "DEFER",
      reason: "NO_VERIFIED_APPLICABLE_CONSTITUTION",
      ruleIds: [],
      constitutionalVersion: "unknown",
      scope: "none",
      authoritative: false,
    };
  }

  const applicable = verifiedRules
    .filter((rule) => isApplicable(rule, request))
    .sort((a, b) => {
      if (b.precedence !== a.precedence) {
        return b.precedence - a.precedence;
      }

      const specificityDifference =
        specificity(b) - specificity(a);

      if (specificityDifference !== 0) {
        return specificityDifference;
      }

      if (a.version !== b.version) {
        return b.version.localeCompare(a.version);
      }

      return a.id.localeCompare(b.id);
    });

  if (applicable.length === 0) {
    return {
      requestId: request.id,
      decision: "DEFER",
      reason: "NO_VERIFIED_APPLICABLE_CONSTITUTION",
      ruleIds: [],
      constitutionalVersion: "unknown",
      scope: "none",
      authoritative: false,
    };
  }

  const globalRules = applicable.filter(
    (rule) => rule.scope === "global",
  );

  const invalidOverride = applicable.find(
    (rule) =>
      violatesGlobalImmutablePrinciple(globalRules, rule),
  );

  if (invalidOverride) {
    return {
      requestId: request.id,
      decision: "DEFER",
      reason: "GLOBAL_IMMUTABLE_PRINCIPLE_CONFLICT",
      ruleIds: [invalidOverride.id, ...globalRules.map((rule) => rule.id)],
      constitutionalVersion: applicable[0]!.version,
      scope: applicable[0]!.scope,
      authoritative: false,
    };
  }

  const conflict = resolveConstitutionalConflict(
    applicable,
    request.action,
  );

  if (conflict !== null) {
    return {
      requestId: request.id,
      decision: "DEFER",
      reason: conflict.reason,
      ruleIds: conflict.ruleIds,
      constitutionalVersion: applicable[0]!.version,
      scope: applicable[0]!.scope,
      authoritative: false,
    };
  }

  const prohibited = applicable.find((rule) =>
    deniesAction(rule, request.action),
  );

  if (prohibited) {
    return {
      requestId: request.id,
      decision: "DENY",
      reason: "CONSTITUTIONALLY_PROHIBITED",
      ruleIds: [prohibited.id],
      constitutionalVersion: prohibited.version,
      scope: prohibited.scope,
      authoritative: false,
    };
  }

  const missingCondition = applicable.find(
    (rule) =>
      rule.requiredConditions.length > 0 &&
      !rule.requiredConditions.every((condition) =>
        request.satisfiedConditions.includes(condition),
      ),
  );

  if (missingCondition) {
    return {
      requestId: request.id,
      decision: "DEFER",
      reason: "CONSTITUTIONAL_CONDITION_UNSATISFIED",
      ruleIds: [missingCondition.id],
      constitutionalVersion: missingCondition.version,
      scope: missingCondition.scope,
    authoritative: false,
    };
  }

  const selected = applicable[0]!;

  return {
    requestId: request.id,
    decision: "ALLOW",
    reason: "CONSTITUTIONALLY_ALLOWED",
    ruleIds: [selected.id],
    constitutionalVersion: selected.version,
    scope: selected.scope,
    authoritative: false,
  };
}

export function constitutionalRulePayload(
  rule: ConstitutionalRule,
): string {
  const { signature: _signature, ...unsignedRule } = rule;
  return JSON.stringify(unsignedRule);
}

export function isConstitutionalRuleVerified(
  rule: ConstitutionalRule,
  publicKeyPem: string,
): boolean {
  validateConstitutionalRule(rule);
  return verifyConstitutionalRule(rule, publicKeyPem);
}
