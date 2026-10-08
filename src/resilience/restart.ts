import { DatabaseSync } from "node:sqlite";
import { sha256 } from "../core/security.js";
import { canonicalize } from "../core/canonical.js";
import {
  validateNonEmpty,
  validateTimestamp,
} from "../core/validation.js";
import { invariant } from "../core/errors.js";
import { createStateTransition } from "./state.js";
import { ResilienceRegistry } from "./registry.js";

export type VerificationType =
  | "HUMAN_FINAL_VERIFICATION"
  | "INDEPENDENT_AUTHORITY_VERIFICATION";

export type VerificationStatus =
  | "PASSED"
  | "FAILED";

export interface FinalVerification {
  id: string;
  verificationType: VerificationType;
  verifierId: string;
  verifiedAt: string;
  status: VerificationStatus;
  evidenceRef: string;
  reason: string;
  verificationHash: string;
}

export interface RestartAuthorization {
  id: string;
  recoveryEvidenceRef: string;
  finalVerificationIds: string[];
  authorizedBy: string;
  authorizedAt: string;
  reason: string;
  authorizationHash: string;
}

function verificationPayload(
  verification: FinalVerification,
): Omit<FinalVerification, "verificationHash"> {
  const { verificationHash: _hash, ...payload } = verification;
  return payload;
}

function authorizationPayload(
  authorization: RestartAuthorization,
): Omit<RestartAuthorization, "authorizationHash"> {
  const { authorizationHash: _hash, ...payload } = authorization;
  return payload;
}

export function createFinalVerification(
  input: Omit<FinalVerification, "verificationHash">,
): FinalVerification {
  validateNonEmpty(
    input.id,
    "RESTART_VERIFICATION_ID_EMPTY",
    "Verification id is required",
  );

  validateNonEmpty(
    input.verifierId,
    "RESTART_VERIFIER_EMPTY",
    "Verifier id is required",
  );

  validateNonEmpty(
    input.evidenceRef,
    "RESTART_VERIFICATION_EVIDENCE_EMPTY",
    "Verification evidence reference is required",
  );

  validateNonEmpty(
    input.reason,
    "RESTART_VERIFICATION_REASON_EMPTY",
    "Verification reason is required",
  );

  validateTimestamp(
    input.verifiedAt,
    "RESTART_VERIFICATION_TIMESTAMP_INVALID",
    "Verification timestamp is invalid",
  );

  invariant(
    input.status === "PASSED",
    "RESTART_VERIFICATION_NOT_PASSED",
    "Only passed final verification can support restart",
  );

  return {
    ...input,
    verificationHash: sha256(
      canonicalize(input),
    ),
  };
}

export function verifyFinalVerification(
  verification: FinalVerification,
): boolean {
  return (
    sha256(canonicalize(verificationPayload(verification))) ===
    verification.verificationHash
  );
}

export function createRestartAuthorization(
  input: Omit<RestartAuthorization, "authorizationHash">,
): RestartAuthorization {
  validateNonEmpty(
    input.id,
    "RESTART_AUTHORIZATION_ID_EMPTY",
    "Restart authorization id is required",
  );

  validateNonEmpty(
    input.recoveryEvidenceRef,
    "RESTART_RECOVERY_EVIDENCE_EMPTY",
    "Recovery evidence reference is required",
  );

  validateNonEmpty(
    input.authorizedBy,
    "RESTART_AUTHORIZER_EMPTY",
    "Restart authorizer is required",
  );

  validateNonEmpty(
    input.reason,
    "RESTART_AUTHORIZATION_REASON_EMPTY",
    "Restart authorization reason is required",
  );

  validateTimestamp(
    input.authorizedAt,
    "RESTART_AUTHORIZATION_TIMESTAMP_INVALID",
    "Restart authorization timestamp is invalid",
  );

  invariant(
    input.finalVerificationIds.length >= 2,
    "RESTART_REQUIRES_INDEPENDENT_VERIFICATION",
    "Controlled restart requires final verification and independent verification",
  );

  invariant(
    new Set(input.finalVerificationIds).size ===
      input.finalVerificationIds.length,
    "RESTART_DUPLICATE_VERIFICATION",
    "Restart verification references must be unique",
  );

  return {
    ...input,
    authorizationHash: sha256(
      canonicalize(input),
    ),
  };
}

export function verifyRestartAuthorization(
  authorization: RestartAuthorization,
): boolean {
  return (
    sha256(
      canonicalize(
        authorizationPayload(authorization),
      ),
    ) === authorization.authorizationHash
  );
}

export class RestartRegistry {
  private readonly db: DatabaseSync;

  constructor(path = ".controlled-restart.sqlite") {
    this.db = new DatabaseSync(path);

    this.db.exec(`
      PRAGMA journal_mode=WAL;

      CREATE TABLE IF NOT EXISTS final_verifications (
        id TEXT PRIMARY KEY,
        verification_type TEXT NOT NULL,
        verifier_id TEXT NOT NULL,
        verified_at TEXT NOT NULL,
        status TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        reason TEXT NOT NULL,
        verification_hash TEXT NOT NULL UNIQUE
      );

      CREATE TABLE IF NOT EXISTS restart_authorizations (
        id TEXT PRIMARY KEY,
        recovery_evidence_ref TEXT NOT NULL,
        final_verification_ids TEXT NOT NULL,
        authorized_by TEXT NOT NULL,
        authorized_at TEXT NOT NULL,
        reason TEXT NOT NULL,
        authorization_hash TEXT NOT NULL UNIQUE
      );

      CREATE TABLE IF NOT EXISTS restart_events (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        authorization_id TEXT NOT NULL,
        detail TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE
      );

      CREATE TRIGGER IF NOT EXISTS restart_verifications_immutable_update
      BEFORE UPDATE ON final_verifications
      BEGIN
        SELECT RAISE(ABORT, 'RESTART_VERIFICATION_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS restart_verifications_append_only_delete
      BEFORE DELETE ON final_verifications
      BEGIN
        SELECT RAISE(ABORT, 'RESTART_VERIFICATION_APPEND_ONLY');
      END;

      CREATE TRIGGER IF NOT EXISTS restart_authorizations_immutable_update
      BEFORE UPDATE ON restart_authorizations
      BEGIN
        SELECT RAISE(ABORT, 'RESTART_AUTHORIZATION_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS restart_authorizations_append_only_delete
      BEFORE DELETE ON restart_authorizations
      BEGIN
        SELECT RAISE(ABORT, 'RESTART_AUTHORIZATION_APPEND_ONLY');
      END;

      CREATE TRIGGER IF NOT EXISTS restart_events_immutable_update
      BEFORE UPDATE ON restart_events
      BEGIN
        SELECT RAISE(ABORT, 'RESTART_EVENT_IMMUTABLE');
      END;

      CREATE TRIGGER IF NOT EXISTS restart_events_append_only_delete
      BEFORE DELETE ON restart_events
      BEGIN
        SELECT RAISE(ABORT, 'RESTART_EVENT_APPEND_ONLY');
      END;
    `);
  }

  putVerification(
    verification: FinalVerification,
  ): void {
    const existing = this.db
      .prepare(`
        SELECT verification_hash
        FROM final_verifications
        WHERE id = ?
      `)
      .get(verification.id) as {
        verification_hash?: string;
      } | undefined;

    if (existing?.verification_hash !== undefined) {
      throw new Error(
        `RESTART_VERIFICATION_ALREADY_EXISTS:${verification.id}`,
      );
    }

    this.db
      .prepare(`
        INSERT INTO final_verifications
          (
            id,
            verification_type,
            verifier_id,
            verified_at,
            status,
            evidence_ref,
            reason,
            verification_hash
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        verification.id,
        verification.verificationType,
        verification.verifierId,
        verification.verifiedAt,
        verification.status,
        verification.evidenceRef,
        verification.reason,
        verification.verificationHash,
      );
  }

  getVerification(
    id: string,
  ): FinalVerification | undefined {
    const row = this.db
      .prepare(`
        SELECT *
        FROM final_verifications
        WHERE id = ?
      `)
      .get(id) as Record<string, unknown> | undefined;

    if (row === undefined) {
      return undefined;
    }

    const verification: FinalVerification = {
      id: String(row.id),
      verificationType: row.verification_type as VerificationType,
      verifierId: String(row.verifier_id),
      verifiedAt: String(row.verified_at),
      status: row.status as VerificationStatus,
      evidenceRef: String(row.evidence_ref),
      reason: String(row.reason),
      verificationHash: String(row.verification_hash),
    };

    if (!verifyFinalVerification(verification)) {
      throw new Error(
        "RESTART_VERIFICATION_INTEGRITY_FAILURE",
      );
    }

    return verification;
  }

  putAuthorization(
    authorization: RestartAuthorization,
  ): void {
    const existing = this.db
      .prepare(`
        SELECT authorization_hash
        FROM restart_authorizations
        WHERE id = ?
      `)
      .get(authorization.id) as {
        authorization_hash?: string;
      } | undefined;

    if (existing?.authorization_hash !== undefined) {
      throw new Error(
        `RESTART_AUTHORIZATION_ALREADY_EXISTS:${authorization.id}`,
      );
    }

    this.db
      .prepare(`
        INSERT INTO restart_authorizations
          (
            id,
            recovery_evidence_ref,
            final_verification_ids,
            authorized_by,
            authorized_at,
            reason,
            authorization_hash
          )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        authorization.id,
        authorization.recoveryEvidenceRef,
        JSON.stringify(
          authorization.finalVerificationIds,
        ),
        authorization.authorizedBy,
        authorization.authorizedAt,
        authorization.reason,
        authorization.authorizationHash,
      );
  }

  getAuthorization(
    id: string,
  ): RestartAuthorization | undefined {
    const row = this.db
      .prepare(`
        SELECT *
        FROM restart_authorizations
        WHERE id = ?
      `)
      .get(id) as Record<string, unknown> | undefined;

    if (row === undefined) {
      return undefined;
    }

    const authorization: RestartAuthorization = {
      id: String(row.id),
      recoveryEvidenceRef: String(
        row.recovery_evidence_ref,
      ),
      finalVerificationIds: JSON.parse(
        String(row.final_verification_ids),
      ) as string[],
      authorizedBy: String(row.authorized_by),
      authorizedAt: String(row.authorized_at),
      reason: String(row.reason),
      authorizationHash: String(
        row.authorization_hash,
      ),
    };

    if (!verifyRestartAuthorization(authorization)) {
      throw new Error(
        "RESTART_AUTHORIZATION_INTEGRITY_FAILURE",
      );
    }

    return authorization;
  }

  putRestartEvent(
    id: string,
    eventType: string,
    occurredAt: string,
    authorizationId: string,
    detail: string,
  ): void {
    validateTimestamp(
      occurredAt,
      "RESTART_EVENT_TIMESTAMP_INVALID",
      "Restart event timestamp is invalid",
    );

    const payload = {
      id,
      eventType,
      occurredAt,
      authorizationId,
      detail,
    };

    const eventHash = sha256(
      canonicalize(payload),
    );

    this.db
      .prepare(`
        INSERT INTO restart_events
          (
            id,
            event_type,
            occurred_at,
            authorization_id,
            detail,
            event_hash
          )
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .run(
        id,
        eventType,
        occurredAt,
        authorizationId,
        detail,
        eventHash,
      );
  }

  listRestartEvents(): Array<{
    id: string;
    eventType: string;
    occurredAt: string;
    authorizationId: string;
    detail: string;
    eventHash: string;
  }> {
    const rows = this.db
      .prepare(`
        SELECT *
        FROM restart_events
        ORDER BY rowid ASC
      `)
      .all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      id: String(row.id),
      eventType: String(row.event_type),
      occurredAt: String(row.occurred_at),
      authorizationId: String(
        row.authorization_id,
      ),
      detail: String(row.detail),
      eventHash: String(row.event_hash),
    }));
  }

  close(): void {
    this.db.close();
  }
}

export class ControlledRestartService {
  constructor(
    private readonly resilience: ResilienceRegistry,
    private readonly restart: RestartRegistry,
  ) {}

  recordFinalVerification(
    input: Omit<FinalVerification, "verificationHash">,
  ): FinalVerification {
    const verification =
      createFinalVerification(input);

    this.restart.putVerification(verification);

    return verification;
  }

  authorizeRestart(
    input: Omit<RestartAuthorization, "authorizationHash">,
  ): RestartAuthorization {
    const current =
      this.resilience.getAuthoritativeState();

    if (current !== "RECOVERY") {
      throw new Error(
        "RESTART_AUTHORIZATION_REQUIRES_RECOVERY_STATE",
      );
    }

    if (
      new Set(input.finalVerificationIds).size !==
      input.finalVerificationIds.length
    ) {
      throw new Error(
        "RESTART_DUPLICATE_VERIFICATION",
      );
    }

    const verifications =
      input.finalVerificationIds.map((id) => {
        const verification =
          this.restart.getVerification(id);

        if (verification === undefined) {
          throw new Error(
            `RESTART_VERIFICATION_NOT_FOUND:${id}`,
          );
        }

        if (!verifyFinalVerification(verification)) {
          throw new Error(
            `RESTART_VERIFICATION_INTEGRITY_FAILURE:${id}`,
          );
        }

        if (verification.status !== "PASSED") {
          throw new Error(
            `RESTART_VERIFICATION_NOT_PASSED:${id}`,
          );
        }

        return verification;
      });

    const hasHuman = verifications.some(
      (v) =>
        v.verificationType ===
        "HUMAN_FINAL_VERIFICATION",
    );

    const hasIndependent = verifications.some(
      (v) =>
        v.verificationType ===
        "INDEPENDENT_AUTHORITY_VERIFICATION",
    );

    if (!hasHuman || !hasIndependent) {
      throw new Error(
        "RESTART_REQUIRES_HUMAN_AND_INDEPENDENT_VERIFICATION",
      );
    }

    const distinctVerifiers =
      new Set(
        verifications.map(
          (verification) =>
            verification.verifierId,
        ),
      );

    if (distinctVerifiers.size < 2) {
      throw new Error(
        "RESTART_VERIFIERS_MUST_BE_INDEPENDENT",
      );
    }

    const authorization =
      createRestartAuthorization(input);

    this.restart.putAuthorization(
      authorization,
    );

    return authorization;
  }

  completeControlledRestart(
    authorizationId: string,
    occurredAt: string,
    authorityId: string,
    evidenceRef: string,
  ): void {
    const current =
      this.resilience.getAuthoritativeState();

    if (current !== "RECOVERY") {
      throw new Error(
        "CONTROLLED_RESTART_REQUIRES_RECOVERY_STATE",
      );
    }

    const authorization =
      this.restart.getAuthorization(
        authorizationId,
      );

    if (authorization === undefined) {
      throw new Error(
        "CONTROLLED_RESTART_AUTHORIZATION_NOT_FOUND",
      );
    }

    if (
      !verifyRestartAuthorization(
        authorization,
      )
    ) {
      throw new Error(
        "CONTROLLED_RESTART_AUTHORIZATION_INTEGRITY_FAILURE",
      );
    }

    for (const id of authorization.finalVerificationIds) {
      const verification =
        this.restart.getVerification(id);

      if (
        verification === undefined ||
        !verifyFinalVerification(verification) ||
        verification.status !== "PASSED"
      ) {
        throw new Error(
          `CONTROLLED_RESTART_VERIFICATION_FAILURE:${id}`,
        );
      }
    }

    const transitions =
      this.resilience.listTransitions();

    const previous = transitions.at(-1);

    throw new Error(
      "RESILIENCE_RESTART_AUTHORIZATION_REQUIRED: controlled restart must use the authoritative GIIA pipeline before committing RECOVERY->ONLINE",
    );

    this.restart.putRestartEvent(
      `restart-complete-${authorizationId}`,
      "CONTROLLED_RESTART_COMPLETED",
      occurredAt,
      authorizationId,
      "Consequential operation restored only after required final verification",
    );
  }
}
