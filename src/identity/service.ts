import { invariant } from "../core/errors.js";
import { validateNonEmpty, validateTimestamp } from "../core/validation.js";
import type { Identity } from "./types.js";

export function validateIdentity(identity: Identity): void {
  validateNonEmpty(
    identity.id,
    "IDENTITY_ID_EMPTY",
    "Identity id is required",
  );

  validateNonEmpty(
    identity.provenance,
    "IDENTITY_PROVENANCE_EMPTY",
    "Identity provenance is required",
  );

  validateTimestamp(
    identity.createdAt,
    "IDENTITY_CREATED_AT_INVALID",
    "Identity creation time must be a valid timestamp",
  );

  invariant(
    identity.status !== "unknown",
    "IDENTITY_STATUS_UNKNOWN",
    "Identity status cannot be unknown",
  );
}

export function isUsableIdentity(identity: Identity): boolean {
  return identity.status === "active";
}
