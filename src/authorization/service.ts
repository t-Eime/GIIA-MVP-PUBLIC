import { invariant } from "../core/errors.js";
import type { Identity } from "../identity/types.js";
import type { Authority } from "../authority/types.js";
import { hasScope, isUsableAuthority } from "../authority/service.js";
import { isUsableIdentity } from "../identity/service.js";
import type { AuthorizationRequest, AuthorizationResult } from "./types.js";

export function authorize(
  request: AuthorizationRequest,
  identity: Identity,
  authority: Authority,
): AuthorizationResult {
  invariant(request.id.trim().length > 0, "AUTH_REQUEST_ID_EMPTY", "Authorization request id is required");
  invariant(request.action.trim().length > 0, "AUTH_ACTION_EMPTY", "Authorization action is required");
  invariant(request.resource.trim().length > 0, "AUTH_RESOURCE_EMPTY", "Authorization resource is required");

  if (request.subjectIdentityId !== identity.id) {
    return { requestId: request.id, decision: "DENY", reason: "SUBJECT_IDENTITY_MISMATCH", authoritative: false };
  }

  if (request.authorityId !== authority.id) {
    return { requestId: request.id, decision: "DENY", reason: "AUTHORITY_ID_MISMATCH", authoritative: false };
  }

  if (!isUsableIdentity(identity)) {
    return { requestId: request.id, decision: "DENY", reason: "IDENTITY_NOT_USABLE", authoritative: false };
  }

  if (!isUsableAuthority(authority, request.requestedAt)) {
    return { requestId: request.id, decision: "DENY", reason: "AUTHORITY_NOT_USABLE", authoritative: false };
  }

  if (request.requestedAt < authority.issuedAt) {
    return { requestId: request.id, decision: "DENY", reason: "REQUEST_BEFORE_AUTHORITY", authoritative: false };
  }

  if (!hasScope(authority, request.action, request.resource)) {
    return { requestId: request.id, decision: "DENY", reason: "ACTION_OUTSIDE_SCOPE", authoritative: false };
  }

  return { requestId: request.id, decision: "ALLOW", reason: "AUTHORIZED", authoritative: false };
}
