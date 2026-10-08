import { canonicalize } from "../core/canonical.js";
import {
  createHash,
  createPublicKey,
  verify,
} from "node:crypto";

import {
  passportAllowsCapability,
  verifyAgentPassport,
  type AgentPassport,
} from "../identity/agent-passport.js";

export type EnforcementVerificationDecision =
  | "PERMITTED"
  | "BLOCKED";

export interface GovernanceDecisionReference {
  readonly decisionId: string;
  readonly requestId: string;
  readonly decision: "ALLOW";
  readonly authoritative: true;
  readonly actorId: string;
  readonly action: string;
  readonly target: string;
  readonly payloadHash: string;
  readonly constitutionVersion: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly humanApprovalRequired: boolean;
  readonly humanApprovalVerified: boolean;
  readonly revocationState: "active" | "revoked";
  readonly shutdownState: "clear" | "active";
}

export interface ExternalEnforcementAuthorization {
  readonly authorizationId: string;
  readonly executorId: string;
  readonly decisionId: string;
  readonly requestId: string;
  readonly actorId: string;
  readonly passportId: string;
  readonly action: string;
  readonly target: string;
  readonly payloadHash: string;
  readonly constitutionVersion: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly signingAlgorithm: "Ed25519";
  readonly publicKeyPem: string;
  readonly signatureBase64: string;
}

export interface EnforcementVerificationResult {
  readonly decision: EnforcementVerificationDecision;
  readonly reason: string;
  readonly authorizationHash: string | null;
  readonly passportHash: string | null;
}



function unsignedAuthorization(
  authorization: ExternalEnforcementAuthorization,
): Omit<ExternalEnforcementAuthorization, "signatureBase64"> {
  const { signatureBase64: _signature, ...unsigned } =
    authorization;

  return unsigned;
}

function sha256(value: string): string {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

export function verifyExternalEnforcement(
  decision: GovernanceDecisionReference,
  authorization: ExternalEnforcementAuthorization,
  passport: AgentPassport,
  payload: unknown,
  capability: string,
  at: string,
): EnforcementVerificationResult {
  const blocked = (
    reason: string,
    passportHash: string | null = null,
  ): EnforcementVerificationResult => ({
    decision: "BLOCKED",
    reason,
    authorizationHash: null,
    passportHash,
  });

  if (
    decision.decision !== "ALLOW" ||
    decision.authoritative !== true
  ) {
    return blocked(
      "GOVERNANCE_DECISION_NOT_AUTHORITATIVE_ALLOW",
    );
  }

  if (decision.revocationState !== "active") {
    return blocked("GOVERNANCE_DECISION_REVOKED");
  }

  if (decision.shutdownState !== "clear") {
    return blocked("TERMINAL_SHUTDOWN_ACTIVE");
  }

  if (
    decision.humanApprovalRequired &&
    !decision.humanApprovalVerified
  ) {
    return blocked("REQUIRED_HUMAN_APPROVAL_MISSING");
  }

  const timestamp = Date.parse(at);

  if (!Number.isFinite(timestamp)) {
    return blocked("INVALID_VERIFICATION_TIME");
  }

  if (timestamp >= Date.parse(decision.expiresAt)) {
    return blocked("GOVERNANCE_DECISION_EXPIRED");
  }

  if (timestamp >= Date.parse(authorization.expiresAt)) {
    return blocked("EXTERNAL_AUTHORIZATION_EXPIRED");
  }

  const payloadHash = sha256(canonicalize(payload));

  if (payloadHash !== decision.payloadHash) {
    return blocked("PAYLOAD_HASH_MISMATCH");
  }

  if (
    authorization.decisionId !== decision.decisionId ||
    authorization.requestId !== decision.requestId ||
    authorization.actorId !== decision.actorId ||
    authorization.action !== decision.action ||
    authorization.target !== decision.target ||
    authorization.payloadHash !== decision.payloadHash ||
    authorization.constitutionVersion !==
      decision.constitutionVersion ||
    authorization.nonce !== decision.nonce
  ) {
    return blocked("ENFORCEMENT_BINDING_MISMATCH");
  }

  if (!authorization.executorId) {
    return blocked("EXECUTOR_ID_REQUIRED");
  }

  if (
    !authorization.publicKeyPem ||
    !authorization.signatureBase64
  ) {
    return blocked(
      "EXTERNAL_AUTHORIZATION_SIGNATURE_REQUIRED",
    );
  }

  const passportResult = verifyAgentPassport(
    passport,
    at,
  );

  if (!passportResult.valid) {
    return blocked(
      `AGENT_PASSPORT_INVALID:${passportResult.reason}`,
    );
  }

  if (
    passport.passportId !== authorization.passportId ||
    passport.agentId !== authorization.executorId
  ) {
    return blocked(
      "AGENT_PASSPORT_BINDING_MISMATCH",
      passportResult.passportHash,
    );
  }

  if (!passportAllowsCapability(passport, capability)) {
    return blocked(
      "CAPABILITY_NOT_DECLARED_AND_PERMITTED",
      passportResult.passportHash,
    );
  }

  try {
    const publicKey = createPublicKey(
      authorization.publicKeyPem,
    );

    const validSignature = verify(
      null,
      Buffer.from(
        canonicalize(
          unsignedAuthorization(authorization),
        ),
        "utf8",
      ),
      publicKey,
      Buffer.from(
        authorization.signatureBase64,
        "base64",
      ),
    );

    if (!validSignature) {
      return blocked(
        "EXTERNAL_AUTHORIZATION_SIGNATURE_INVALID",
        passportResult.passportHash,
      );
    }
  } catch {
    return blocked(
      "EXTERNAL_AUTHORIZATION_SIGNATURE_INVALID",
      passportResult.passportHash,
    );
  }

  return {
    decision: "PERMITTED",
    reason:
      "EXTERNAL_ENFORCEMENT_AUTHORIZATION_VERIFIED",
    authorizationHash: sha256(
      canonicalize(authorization),
    ),
    passportHash: passportResult.passportHash,
  };
}

export const EXTERNAL_ENFORCEMENT_BOUNDARY =
  Object.freeze({
    executionAuthority: "NONE",
    executionFunction: null,
    requiresIndependentExecutor: true,
    failClosed: true,
  });
