import type {
  MvpDecisionRecord,
  MvpEvaluateRequest,
} from "./types.js";

const ID_RE = /^[A-Za-z0-9._:-]{1,200}$/;

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`INVALID_${field.toUpperCase()}`);
  }

  return value;
}

export function validateEvaluateRequest(
  value: unknown,
): MvpEvaluateRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("INVALID_REQUEST_BODY");
  }

  const input = value as Record<string, unknown>;

  const forbiddenSecurityFields = [
    "decision",
    "authorized",
    "authorization",
    "trust",
    "trusted",
    "verified",
    "authoritative",
    "executionPermitted",
    "executionAllowed",
    "governanceApproved",
    "constitutionalApproved",
    "provenanceVerified",
  ] as const;

  for (const field of forbiddenSecurityFields) {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      throw new Error(
        `SECURITY_SENSITIVE_FIELD_FORBIDDEN:${field}`,
      );
    }
  }

  const requestId = requiredString(input.requestId, "request_id");
  const action = requiredString(input.action, "action");
  const resource = requiredString(input.resource, "resource");

  if (!ID_RE.test(requestId)) {
    throw new Error("INVALID_REQUEST_ID");
  }

  if (action.length > 200) {
    throw new Error("REQUEST_ACTION_TOO_LONG");
  }

  if (resource.length > 500) {
    throw new Error("REQUEST_RESOURCE_TOO_LONG");
  }

  if (input.requestedAt !== undefined) {
    const requestedAt = requiredString(
      input.requestedAt,
      "requested_at",
    );

    const timestamp = Date.parse(requestedAt);

    if (!Number.isFinite(timestamp)) {
      throw new Error("INVALID_REQUESTED_AT");
    }

    if (timestamp > Date.now() + 60_000) {
      throw new Error("REQUESTED_AT_IN_FUTURE");
    }

    if (Date.now() - timestamp > 24 * 60 * 60 * 1000) {
      throw new Error("REQUESTED_AT_TOO_OLD");
    }

    return {
      requestId,
      action,
      resource,
      requestedAt,
    };
  }

  return {
    requestId,
    action,
    resource,
    requestedAt: new Date().toISOString(),
  };
}

export function validateDecisionRecord(
  value: unknown,
): MvpDecisionRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("INVALID_DECISION_RECORD");
  }

  const r = value as Record<string, unknown>;

  if (r.version !== "1") {
    throw new Error("INVALID_RECORD_VERSION");
  }

  if (r.recordType !== "GIIA_AUTHORITATIVE_DECISION") {
    throw new Error("INVALID_RECORD_TYPE");
  }

  /*
   * Security-critical boundary checks intentionally precede
   * ordinary required-field validation. A caller attempting to
   * turn an authoritative decision into executable authority must
   * receive the execution-boundary failure even if another field
   * is also malformed or absent.
   */
  if (r.authoritative !== true) {
    throw new Error("DECISION_NOT_AUTHORITATIVE");
  }

  if (r.executionPermitted !== false) {
    throw new Error("EXECUTION_AUTHORITY_FORBIDDEN");
  }

  const fields = [
    "decisionId",
    "requestId",
    "action",
    "resource",
    "decision",
    "reason",
    "provenance",
    "issuedAt",
    "signerKeyId",
    "signerPublicKeyPem",
    "signature",
  ];

  for (const field of fields) {
    requiredString(r[field], field);
  }

  if (
    !r.executionBinding ||
    typeof r.executionBinding !== "object" ||
    Array.isArray(r.executionBinding)
  ) {
    throw new Error("MISSING_EXECUTION_BINDING");
  }

  const binding = r.executionBinding as Record<string, unknown>;

  for (const field of [
    "actorId",
    "target",
    "payloadHash",
    "constitutionVersion",
    "nonce",
    "expiresAt",
  ]) {
    requiredString(
      binding[field],
      `execution_binding_${field}`,
    );
  }

  if (!Number.isFinite(Date.parse(binding.expiresAt as string))) {
    throw new Error("INVALID_EXECUTION_BINDING_EXPIRY");
  }

  if (
    Date.parse(binding.expiresAt as string) <=
    Date.parse(r.issuedAt as string)
  ) {
    throw new Error("INVALID_EXECUTION_BINDING_WINDOW");
  }

  const nestedRequiredFields = [
    "governanceAuthorization",
    "governanceAuthorizationFingerprint",
    "governanceKey",
    "governanceCredential",
    "governanceTrustChain",
    "signingAuthorityId",
  ];

  for (const field of nestedRequiredFields) {
    if (
      r[field] === undefined ||
      r[field] === null
    ) {
      throw new Error(
        `MISSING_${field.toUpperCase()}`,
      );
    }
  }

  if (!["ALLOW", "DENY", "DEFER"].includes(r.decision as string)) {
    throw new Error("INVALID_DECISION");
  }

  if (!ID_RE.test(r.requestId as string)) {
    throw new Error("INVALID_REQUEST_ID");
  }

  if (!Number.isFinite(Date.parse(r.issuedAt as string))) {
    throw new Error("INVALID_ISSUED_AT");
  }

  return r as unknown as MvpDecisionRecord;
}
