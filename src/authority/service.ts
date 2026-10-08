import { invariant } from "../core/errors.js";
import {
  validateNonEmpty,
  validateTimestamp,
} from "../core/validation.js";
import type { Authority } from "./types.js";

export function validateAuthority(authority: Authority): void {
  validateNonEmpty(
    authority.id,
    "AUTHORITY_ID_EMPTY",
    "Authority id is required",
  );

  validateNonEmpty(
    authority.holderIdentityId,
    "AUTHORITY_HOLDER_EMPTY",
    "Authority holder is required",
  );

  validateNonEmpty(
    authority.trustCredentialId,
    "AUTHORITY_TRUST_CREDENTIAL_EMPTY",
    "Authority trust credential is required",
  );

  invariant(
    authority.scope.length > 0,
    "AUTHORITY_SCOPE_EMPTY",
    "Authority scope cannot be empty",
  );

  for (const scope of authority.scope) {
    validateNonEmpty(
      scope,
      "AUTHORITY_SCOPE_ENTRY_EMPTY",
      "Authority scope entries cannot be empty",
    );
  }

  validateNonEmpty(
    authority.issuer,
    "AUTHORITY_ISSUER_EMPTY",
    "Authority issuer is required",
  );

  validateNonEmpty(
    authority.provenance,
    "AUTHORITY_PROVENANCE_EMPTY",
    "Authority provenance is required",
  );

  validateTimestamp(
    authority.issuedAt,
    "AUTHORITY_ISSUED_AT_INVALID",
    "Authority issuance time must be a valid timestamp",
  );

  invariant(
    authority.status !== "unknown",
    "AUTHORITY_STATUS_UNKNOWN",
    "Authority status cannot be unknown",
  );

  if (authority.expiresAt !== undefined) {
    validateTimestamp(
      authority.expiresAt,
      "AUTHORITY_EXPIRES_AT_INVALID",
      "Authority expiry must be a valid timestamp",
    );

    invariant(
      authority.expiresAt > authority.issuedAt,
      "AUTHORITY_EXPIRY_INVALID",
      "Authority expiry must be after issuance",
    );
  }
}

export function isUsableAuthority(authority: Authority, at: string): boolean {
  if (authority.status !== "active") return false;
  if (at < authority.issuedAt) return false;
  if (authority.expiresAt !== undefined && at >= authority.expiresAt) return false;
  return true;
}

export function hasScope(
  authority: Authority,
  action: string,
  resource: string,
): boolean {
  return authority.scope.includes(`${action}:${resource}`);
}
