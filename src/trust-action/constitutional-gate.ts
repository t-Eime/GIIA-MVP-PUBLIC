import type { Authority as GIIAAuthority } from "../authority/types.js";
import { hasScope, isUsableAuthority } from "../authority/service.js";
import type { AuthorizationResult } from "../authorization/types.js";
import type { ConstitutionalResult } from "../constitution/types.js";
import type { ActionIntent } from "../trust-action/types.js";
import type { TrustCredential, TrustVerificationResult } from "../trust/types.js";

export type ConstitutionalGateInput = {
  authority: GIIAAuthority;
  credential: TrustCredential;
  action: ActionIntent;
  trust: TrustVerificationResult;
  authorization: AuthorizationResult;
  constitution: ConstitutionalResult | null;
};

export type ConstitutionalGateResult =
  | {
      allowed: true;
      authoritative: true;
      reason: "CONSTITUTIONAL_GATE_PASSED";
    }
  | {
      allowed: false;
      authoritative: false;
      reason: string;
    };

export function constitutionalGate(
  input: ConstitutionalGateInput,
  at: string,
): ConstitutionalGateResult {
  if (!input.trust.valid) {
    return {
      allowed: false,
      authoritative: false,
      reason: `TRUST_${input.trust.reason}`,
    };
  }

  if (input.credential.id !== input.authority.trustCredentialId) {
    return {
      allowed: false,
      authoritative: false,
      reason: "AUTHORITY_CREDENTIAL_MISMATCH",
    };
  }

  if (input.credential.claims.authorityId !== input.authority.id) {
    return {
      allowed: false,
      authoritative: false,
      reason: "CREDENTIAL_AUTHORITY_BINDING_INVALID",
    };
  }

  if (input.credential.subject !== input.authority.holderIdentityId) {
    return {
      allowed: false,
      authoritative: false,
      reason: "CREDENTIAL_HOLDER_BINDING_INVALID",
    };
  }

  if (!isUsableAuthority(input.authority, at)) {
    return {
      allowed: false,
      authoritative: false,
      reason: "AUTHORITY_NOT_USABLE",
    };
  }

  if (
    input.action.actor !== input.authority.holderIdentityId ||
    input.action.action === "" ||
    input.action.resource === ""
  ) {
    return {
      allowed: false,
      authoritative: false,
      reason: "ACTION_IDENTITY_BINDING_INVALID",
    };
  }

  if (
    !hasScope(
      input.authority,
      input.action.action,
      input.action.resource,
    )
  ) {
    return {
      allowed: false,
      authoritative: false,
      reason: "AUTHORITY_SCOPE_DENIED",
    };
  }

  if (input.authorization.decision !== "ALLOW") {
    return {
      allowed: false,
      authoritative: false,
      reason: "AUTHORIZATION_NOT_ALLOWED",
    };
  }

  if (input.constitution !== null && input.constitution.decision !== "ALLOW") {
    return {
      allowed: false,
      authoritative: false,
      reason: "CONSTITUTION_NOT_ALLOWED",
    };
  }

  return {
    allowed: true,
    authoritative: true,
    reason: "CONSTITUTIONAL_GATE_PASSED",
  };
}
