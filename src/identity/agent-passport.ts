import { canonicalize } from "../core/canonical.js";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import type {
  PassportIssuerRegistry,
  PassportIssuer,
} from "./passport-issuer-registry.js";

export type AgentLifecycle =
  | "production"
  | "experimental"
  | "research"
  | "sandbox"
  | "suspended"
  | "revoked";

export interface AgentPassport {
  readonly passportId: string;
  readonly agentId: string;
  readonly issuerId: string;
  readonly origin: string;
  readonly jurisdiction: string;
  readonly operatorId: string;
  readonly ownerId: string;
  readonly agentType: string;
  readonly modelType: string;
  readonly lifecycle: AgentLifecycle;
  readonly deploymentEnvironment: string;
  readonly declaredCapabilities: readonly string[];
  readonly permittedCapabilities: readonly string[];
  readonly credentialIds: readonly string[];
  readonly delegationIds: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt?: string;

  /*
   * Agent identity proof.
   *
   * publicKeyPem belongs to the AGENT.
   * signatureBase64 is made by the AGENT.
   */
  readonly signingAlgorithm: "Ed25519";
  readonly publicKeyPem: string;
  readonly signatureBase64: string;

  /*
   * Independent issuer proof.
   *
   * issuerKeyId identifies the specific issuer signing key.
   * issuerSignatureBase64 is made by the ISSUER.
   */
  readonly issuerKeyId?: string;
  readonly issuerSignatureBase64?: string;

  readonly revocationReference?: string;
}

export interface AgentPassportVerification {
  readonly valid: boolean;
  readonly passportHash: string | null;
  readonly reason: string;
}

function unsignedAgentPassport(
  passport: AgentPassport,
): Omit<
  AgentPassport,
  "signatureBase64" |
    "issuerSignatureBase64"
> {
  const {
    signatureBase64: _agentSignature,
    issuerSignatureBase64: _issuerSignature,
    ...unsigned
  } = passport;

  return unsigned;
}

function agentSignedPassport(
  passport: AgentPassport,
): Omit<AgentPassport, "issuerSignatureBase64"> {
  const {
    issuerSignatureBase64: _issuerSignature,
    ...agentSigned
  } = passport;

  return agentSigned;
}

export function hashAgentPassport(
  passport: AgentPassport,
): string {
  return createHash("sha256")
    .update(canonicalize(passport), "utf8")
    .digest("hex");
}

export function createAgentPassportKeyPair(): {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
} {
  return generateKeyPairSync("ed25519");
}

/*
 * Legacy/self-signed constructor.
 *
 * This remains available for compatibility.
 * It MUST NOT be accepted by the strict external enforcement
 * boundary without independent issuer verification.
 */
export function createAgentPassport(
  input: Omit<
    AgentPassport,
    "signatureBase64" |
      "signingAlgorithm" |
      "issuerKeyId" |
      "issuerSignatureBase64"
  >,
  privateKey: KeyObject,
): AgentPassport {
  const unsigned = {
    ...input,
    signingAlgorithm: "Ed25519" as const,
  };

  const signatureBase64 = sign(
    null,
    Buffer.from(canonicalize(unsigned), "utf8"),
    privateKey,
  ).toString("base64");

  return Object.freeze({
    ...unsigned,
    signatureBase64,
  });
}

export function createIssuerSignedAgentPassport(
  input: Omit<
    AgentPassport,
    "signatureBase64" |
      "signingAlgorithm" |
      "issuerKeyId" |
      "issuerSignatureBase64"
  >,
  agentPrivateKey: KeyObject,
  issuerKeyId: string,
  issuerPrivateKey: KeyObject,
): AgentPassport {
  if (!issuerKeyId) {
    throw new Error("ISSUER_KEY_ID_REQUIRED");
  }

  const agentUnsigned = {
    ...input,
    signingAlgorithm: "Ed25519" as const,
    issuerKeyId,
  };

  /*
   * Agent signs the identity-bearing passport.
   */
  const signatureBase64 = sign(
    null,
    Buffer.from(canonicalize(agentUnsigned), "utf8"),
    agentPrivateKey,
  ).toString("base64");

  const agentSigned = {
    ...agentUnsigned,
    signatureBase64,
  };

  /*
   * Issuer signs the complete agent-signed passport.
   *
   * Therefore the issuer signature commits to:
   *   - agentId
   *   - publicKeyPem
   *   - capabilities
   *   - issuerId
   *   - issuerKeyId
   *   - agent signature
   *   - all other passport metadata
   */
  const issuerSignatureBase64 = sign(
    null,
    Buffer.from(canonicalize(agentSigned), "utf8"),
    issuerPrivateKey,
  ).toString("base64");

  return Object.freeze({
    ...agentSigned,
    issuerSignatureBase64,
  });
}

export function verifyAgentPassport(
  passport: AgentPassport,
  at: string,
): AgentPassportVerification {
  try {
    if (
      !passport.passportId ||
      !passport.agentId ||
      !passport.issuerId
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "IDENTITY_FIELDS_REQUIRED",
      };
    }

    if (!passport.operatorId || !passport.ownerId) {
      return {
        valid: false,
        passportHash: null,
        reason: "OPERATOR_AND_OWNER_REQUIRED",
      };
    }

    if (!passport.origin || !passport.jurisdiction) {
      return {
        valid: false,
        passportHash: null,
        reason: "ORIGIN_AND_JURISDICTION_REQUIRED",
      };
    }

    if (!passport.deploymentEnvironment) {
      return {
        valid: false,
        passportHash: null,
        reason: "DEPLOYMENT_ENVIRONMENT_REQUIRED",
      };
    }

    if (
      !passport.publicKeyPem ||
      !passport.signatureBase64
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "SIGNED_IDENTITY_REQUIRED",
      };
    }

    if (
      passport.lifecycle === "revoked" ||
      passport.lifecycle === "suspended"
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "AGENT_LIFECYCLE_NOT_EXECUTABLE",
      };
    }

    const timestamp = Date.parse(at);
    const issued = Date.parse(passport.issuedAt);

    if (
      !Number.isFinite(timestamp) ||
      !Number.isFinite(issued)
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "INVALID_TIMESTAMP",
      };
    }

    if (timestamp < issued) {
      return {
        valid: false,
        passportHash: null,
        reason: "PASSPORT_NOT_YET_VALID",
      };
    }

    if (
      passport.expiresAt &&
      timestamp >= Date.parse(passport.expiresAt)
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "PASSPORT_EXPIRED",
      };
    }

    if (
      !Array.isArray(passport.declaredCapabilities) ||
      passport.declaredCapabilities.length === 0
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "DECLARED_CAPABILITIES_REQUIRED",
      };
    }

    const publicKey = createPublicKey(
      passport.publicKeyPem,
    );

    /*
     * Verify the AGENT signature independently.
     */
    const agentValid = verify(
      null,
      Buffer.from(
        canonicalize(
          unsignedAgentPassport(passport),
        ),
        "utf8",
      ),
      publicKey,
      Buffer.from(
        passport.signatureBase64,
        "base64",
      ),
    );

    if (!agentValid) {
      return {
        valid: false,
        passportHash: null,
        reason: "PASSPORT_SIGNATURE_INVALID",
      };
    }

    return {
      valid: true,
      passportHash: hashAgentPassport(passport),
      reason: "PASSPORT_VALID",
    };
  } catch {
    return {
      valid: false,
      passportHash: null,
      reason: "PASSPORT_VERIFICATION_FAILED",
    };
  }
}

export function verifyAgentPassportIssuerSignature(
  passport: AgentPassport,
  issuerPublicKeyPem: string,
): boolean {
  try {
    if (
      !passport.issuerKeyId ||
      !passport.issuerSignatureBase64
    ) {
      return false;
    }

    return verify(
      null,
      Buffer.from(
        canonicalize(
          agentSignedPassport(passport),
        ),
        "utf8",
      ),
      createPublicKey(issuerPublicKeyPem),
      Buffer.from(
        passport.issuerSignatureBase64,
        "base64",
      ),
    );
  } catch {
    return false;
  }
}

export function verifyAgentPassportWithIssuer(
  passport: AgentPassport,
  at: string,
  registry: PassportIssuerRegistry,
): AgentPassportVerification {
  try {
    if (
      !passport.issuerKeyId ||
      !passport.issuerSignatureBase64
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "ISSUER_SIGNATURE_REQUIRED",
      };
    }

    /*
     * Establish issuer trust BEFORE accepting any passport signature.
     * The issuer registry is the trust anchor for the issuer key.
     */
    const issuer = registry.getIssuer(
      passport.issuerId,
    );

    if (!issuer) {
      return {
        valid: false,
        passportHash: null,
        reason: "PASSPORT_ISSUER_UNKNOWN",
      };
    }

    if (
      issuer.status !== "ACTIVE" &&
      issuer.status !== "active"
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "PASSPORT_ISSUER_NOT_ACTIVE",
      };
    }

    if (
      issuer.issuerKeyId !==
      passport.issuerKeyId
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "PASSPORT_ISSUER_KEY_MISMATCH",
      };
    }

    const timestamp = Date.parse(at);

    if (!Number.isFinite(timestamp)) {
      return {
        valid: false,
        passportHash: null,
        reason: "INVALID_TIMESTAMP",
      };
    }

    if (
      issuer.notBefore &&
      timestamp < Date.parse(issuer.notBefore)
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "PASSPORT_ISSUER_NOT_YET_VALID",
      };
    }

    if (
      issuer.notAfter &&
      timestamp >= Date.parse(issuer.notAfter)
    ) {
      return {
        valid: false,
        passportHash: null,
        reason: "PASSPORT_ISSUER_EXPIRED",
      };
    }

    /*
     * The issuer signature covers the complete agent-signed
     * passport. Verify it before accepting the passport.
     */
    if (
      !verifyAgentPassportIssuerSignature(
        passport,
        issuer.publicKeyPem,
      )
    ) {
      return {
        valid: false,
        passportHash: null,
        reason:
          "PASSPORT_ISSUER_SIGNATURE_INVALID",
      };
    }

    /*
     * Only after issuer authenticity is established do we
     * validate the agent signature and passport semantics.
     */
    const base = verifyAgentPassport(
      passport,
      at,
    );

    if (!base.valid) {
      return base;
    }

    return {
      valid: true,
      passportHash: hashAgentPassport(passport),
      reason:
        "PASSPORT_VALID_WITH_TRUSTED_ISSUER",
    };
  } catch {
    return {
      valid: false,
      passportHash: null,
      reason:
        "PASSPORT_ISSUER_VERIFICATION_FAILED",
    };
  }
}

export function passportAllowsCapability(
  passport: AgentPassport,
  capability: string,
): boolean {
  return (
    passport.declaredCapabilities.includes(
      capability,
    ) &&
    passport.permittedCapabilities.includes(
      capability,
    )
  );
}
