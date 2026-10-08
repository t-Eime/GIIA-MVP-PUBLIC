import { createHash } from "node:crypto";

export type GovernanceSigningMode =
  | "PRODUCTION_HARDWARE_THRESHOLD"
  | "DEVELOPMENT_SOFTWARE_MULTISIG";

export interface GovernanceSigningProvider {
  readonly mode: GovernanceSigningMode;
  readonly productionReady: boolean;
  readonly providerId: string;

  sign(payload: Uint8Array): Promise<Uint8Array>;
}

export class GovernanceSecureSignerUnavailableError extends Error {
  readonly code = "GOVERNANCE_SECURE_SIGNER_UNAVAILABLE";

  constructor() {
    super(
      "Production governance signing requires an approved hardware-backed threshold signing provider",
    );
    this.name = "GovernanceSecureSignerUnavailableError";
  }
}

/**
 * Production boundary.
 *
 * Deliberately refuses to sign until a real approved HSM/MPC/threshold
 * implementation is connected. This is fail-closed, not fake HSM support.
 */
export function createProductionGovernanceSigningProvider(): GovernanceSigningProvider {
  return {
    mode: "PRODUCTION_HARDWARE_THRESHOLD",
    productionReady: false,
    providerId: "UNCONFIGURED_PRODUCTION_SIGNER",

    async sign(_payload: Uint8Array): Promise<Uint8Array> {
      throw new GovernanceSecureSignerUnavailableError();
    },
  };
}

/**
 * Development/test boundary only.
 *
 * Existing Ed25519 3-of-5 governance multisig remains available to the
 * existing MVP test infrastructure. It must never be presented as HSM,
 * MPC, or true threshold cryptography.
 */
export function createDevelopmentGovernanceSigningProvider(
  signer: (payload: Uint8Array) => Promise<Uint8Array>,
): GovernanceSigningProvider {
  return {
    mode: "DEVELOPMENT_SOFTWARE_MULTISIG",
    productionReady: false,
    providerId: "SOFTWARE_ED25519_MULTISIG_DEV_ONLY",

    async sign(payload: Uint8Array): Promise<Uint8Array> {
      if (!(payload instanceof Uint8Array) || payload.length === 0) {
        throw new Error("GOVERNANCE_SIGNING_PAYLOAD_REQUIRED");
      }

      return signer(payload);
    },
  };
}

export function governanceSigningPayloadDigest(
  payload: Uint8Array,
): string {
  return createHash("sha256").update(payload).digest("hex");
}
