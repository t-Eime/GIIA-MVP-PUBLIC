import {
  verifyTrustChain,
} from ".././trust/service.js";

import type {
  TrustChainInput,
} from ".././trust/service.js";

import {
  verifyAgentPassport,
  passportAllowsCapability,
} from "./agent-passport.js";

import type {
  AgentPassport,
} from "./agent-passport.js";

export type AgentTrustBoundaryDecision =
  | "TRUSTED"
  | "BLOCKED";

export interface AgentTrustBoundaryInput {
  readonly passport: AgentPassport;
  readonly trustChain: TrustChainInput;
  readonly requiredCapability: string;
  readonly expectedAgentId: string;
  readonly expectedIssuerId: string;
  readonly expectedOperatorId?: string;
  readonly expectedOwnerId?: string;
  readonly at: string;
}

export interface AgentTrustBoundaryResult {
  readonly decision: AgentTrustBoundaryDecision;
  readonly passportHash?: string;
  readonly reason:
    | "VALID"
    | "TRUST_CHAIN_INVALID"
    | "PASSPORT_INVALID"
    | "AGENT_ID_MISMATCH"
    | "ISSUER_MISMATCH"
    | "OPERATOR_MISMATCH"
    | "OWNER_MISMATCH"
    | "CAPABILITY_NOT_PERMITTED"
    | "TIME_INVALID";
}

function blocked(
  reason: AgentTrustBoundaryResult["reason"],
): AgentTrustBoundaryResult {
  return Object.freeze({
    decision: "BLOCKED",
    reason,
  });
}

export function verifyAgentTrustBoundary(
  input: AgentTrustBoundaryInput,
): AgentTrustBoundaryResult {
  const {
    passport,
    trustChain,
    requiredCapability,
    expectedAgentId,
    expectedIssuerId,
    expectedOperatorId,
    expectedOwnerId,
    at,
  } = input;

  if (!at || !passport.issuedAt) {
    return blocked("TIME_INVALID");
  }

  if (passport.agentId !== expectedAgentId) {
    return blocked("AGENT_ID_MISMATCH");
  }

  if (passport.issuerId !== expectedIssuerId) {
    return blocked("ISSUER_MISMATCH");
  }

  if (
    expectedOperatorId !== undefined &&
    passport.operatorId !== expectedOperatorId
  ) {
    return blocked("OPERATOR_MISMATCH");
  }

  if (
    expectedOwnerId !== undefined &&
    passport.ownerId !== expectedOwnerId
  ) {
    return blocked("OWNER_MISMATCH");
  }

  const passportResult = verifyAgentPassport(passport, at);

  if (!passportResult.valid) {
    return blocked("PASSPORT_INVALID");
  }

  if (!passportAllowsCapability(passport, requiredCapability)) {
    return blocked("CAPABILITY_NOT_PERMITTED");
  }

  if (
    trustChain.credential.subject !== passport.agentId &&
    trustChain.delegation.delegateeId !== passport.agentId
  ) {
    return blocked("AGENT_ID_MISMATCH");
  }

  if (
    trustChain.root.subject !== passport.issuerId &&
    trustChain.anchor.subject !== passport.issuerId
  ) {
    return blocked("ISSUER_MISMATCH");
  }

  const trustResult = verifyTrustChain(trustChain);

  if (!trustResult.valid) {
    return blocked("TRUST_CHAIN_INVALID");
  }

  return Object.freeze({
    decision: "TRUSTED",
    reason: "VALID",
  });
}

export function assertAgentTrustBoundary(
  input: AgentTrustBoundaryInput,
): AgentTrustBoundaryResult {
  const result = verifyAgentTrustBoundary(input);

  if (result.decision !== "TRUSTED") {
    throw new Error(
      `GIIA_AGENT_TRUST_BOUNDARY_BLOCKED:${result.reason}`,
    );
  }

  return result;
}
