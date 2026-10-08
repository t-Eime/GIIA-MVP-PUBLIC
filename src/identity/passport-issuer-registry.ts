import { createPublicKey } from "node:crypto";

export type PassportIssuerStatus =
  | "active"
  | "suspended"
  | "revoked"
  | "ACTIVE"
  | "SUSPENDED"
  | "REVOKED";

export interface PassportIssuer {
  readonly issuerId: string;
  readonly issuerKeyId?: string;
  readonly jurisdiction: string;
  readonly purpose: string;
  readonly provenance: string;
  readonly publicKeyPem: string;
  readonly status: PassportIssuerStatus;
  readonly notBefore?: string;
  readonly notAfter?: string;
}

export interface PassportIssuerRegistry {
  getIssuer(issuerId: string): PassportIssuer | null;
}

function validWindow(
  issuer: PassportIssuer,
  at: string,
): boolean {
  const timestamp = Date.parse(at);

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  if (
    issuer.notBefore &&
    timestamp < Date.parse(issuer.notBefore)
  ) {
    return false;
  }

  if (
    issuer.notAfter &&
    timestamp >= Date.parse(issuer.notAfter)
  ) {
    return false;
  }

  return true;
}

export class InMemoryPassportIssuerRegistry
  implements PassportIssuerRegistry
{
  private readonly issuers = new Map<
    string,
    PassportIssuer
  >();

  registerIssuer(issuer: PassportIssuer): void {
    if (!issuer.issuerId) {
      throw new Error("ISSUER_ID_REQUIRED");
    }

    // issuerKeyId is optional for legacy registry records.
    // Strict issuer verification requires it through
    // isTrustedIssuer().
    if (!issuer.publicKeyPem) {
      throw new Error("ISSUER_PUBLIC_KEY_REQUIRED");
    }

    createPublicKey(issuer.publicKeyPem);

    if (
      issuer.notBefore &&
      !Number.isFinite(Date.parse(issuer.notBefore))
    ) {
      throw new Error("INVALID_ISSUER_NOT_BEFORE");
    }

    if (
      issuer.notAfter &&
      !Number.isFinite(Date.parse(issuer.notAfter))
    ) {
      throw new Error("INVALID_ISSUER_NOT_AFTER");
    }

    if (
      issuer.notBefore &&
      issuer.notAfter &&
      Date.parse(issuer.notBefore) >= Date.parse(issuer.notAfter)
    ) {
      throw new Error("INVALID_ISSUER_WINDOW");
    }

    const existing = this.issuers.get(issuer.issuerId);

    if (existing) {
      /*
       * An issuer ID is an immutable trust identity.
       * Any attempt to re-bind it to a different key or
       * alter its registered state is a trust-state conflict.
       */
      if (
        existing.issuerKeyId !== issuer.issuerKeyId ||
        existing.publicKeyPem !== issuer.publicKeyPem ||
        existing.status !== issuer.status ||
        existing.jurisdiction !== issuer.jurisdiction ||
        existing.purpose !== issuer.purpose ||
        existing.provenance !== issuer.provenance ||
        existing.notBefore !== issuer.notBefore ||
        existing.notAfter !== issuer.notAfter
      ) {
        throw new Error("PASSPORT_ISSUER_STATE_MISMATCH");
      }

      return;
    }

    this.issuers.set(
      issuer.issuerId,
      Object.freeze({ ...issuer }),
    );
  }

  getIssuer(issuerId: string): PassportIssuer | null {
    return this.issuers.get(issuerId) ?? null;
  }

  isTrustedIssuer(
    issuerId: string,
    issuerKeyId: string,
    at: string,
  ): boolean {
    const issuer = this.getIssuer(issuerId);

    return Boolean(
      issuer &&
        (issuer.status === "active" ||
          issuer.status === "ACTIVE") &&
        Boolean(issuer.issuerKeyId) &&
        issuer.issuerKeyId === issuerKeyId &&
        validWindow(issuer, at),
    );
  }

  /*
   * Backward-compatible API retained from the original registry.
   */
  register(issuer: PassportIssuer): void {
    this.registerIssuer(issuer);
  }

  /*
   * Backward-compatible trust lookup.
   *
   * Original API:
   *   isTrusted(issuerId, at)
   *
   * A legacy key-ID form is also accepted for compatibility with
   * intermediate P0.1 callers, but strict verification must use
   * isTrustedIssuer().
   */
  isTrusted(
    issuerId: string,
    atOrIssuerKeyId: string,
  ): boolean {
    const issuer = this.getIssuer(issuerId);

    if (
      !issuer ||
      (issuer.status !== "active" &&
        issuer.status !== "ACTIVE")
    ) {
      return false;
    }

    // Original registry contract: second argument is an
    // evaluation timestamp.
    if (
      atOrIssuerKeyId.includes("T") ||
      atOrIssuerKeyId.endsWith("Z")
    ) {
      return validWindow(issuer, atOrIssuerKeyId);
    }

    // Compatibility with the intermediate P0.1 two-argument
    // key-ID form. Strict callers must use isTrustedIssuer().
    return Boolean(
      issuer.issuerKeyId &&
      issuer.issuerKeyId === atOrIssuerKeyId,
    );
  }
}
