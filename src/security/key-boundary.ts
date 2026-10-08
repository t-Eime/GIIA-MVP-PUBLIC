import { invariant } from "../core/errors.js";
import { verifyCanonical, signCanonical } from "../trust/crypto.js";
import type { TrustKey } from "../trust/types.js";

export type KeyLifecycleEvent =
  | "REGISTERED"
  | "USED_FOR_SIGNING"
  | "ROTATED"
  | "REVOKED"
  | "QUARANTINED"
  | "RETIRED";

export interface KeyLifecycleRecord {
  sequence: number;
  keyId: string;
  event: KeyLifecycleEvent;
  at: string;
  reason?: string;
}

interface ManagedKey {
  key: TrustKey;
  privateKeyPem: string;
  quarantined: boolean;
}

export class KeySecurityBoundary {
  private readonly keys = new Map<string, ManagedKey>();
  private readonly lifecycle: KeyLifecycleRecord[] = [];
  private sequence = 0;

  register(
    key: TrustKey,
    privateKeyPem: string,
    at: string,
  ): void {
    invariant(
      key.status === "active",
      "KEY_REGISTRATION_REQUIRES_ACTIVE_KEY",
      `Key ${key.id} is not active`,
    );

    invariant(
      !this.keys.has(key.id),
      "KEY_ALREADY_REGISTERED",
      `Key ${key.id} is already registered`,
    );

    invariant(
      privateKeyPem.trim().length > 0,
      "PRIVATE_KEY_REQUIRED",
      "Private key material is required",
    );

    let keyPairBound = false;

    try {
      const probe = {
        purpose: "GIIA-KEY-BINDING",
        keyId: key.id,
      };

      const probeSignature = signCanonical(
        probe,
        privateKeyPem,
      );

      keyPairBound = verifyCanonical(
        probe,
        probeSignature,
        key.publicKeyPem,
      );
    } catch {
      keyPairBound = false;
    }

    invariant(
      keyPairBound,
      "KEY_PRIVATE_PUBLIC_BINDING_INVALID",
      `Private key material does not match public key ${key.id}`,
    );

    this.keys.set(key.id, {
      key: structuredClone(key),
      privateKeyPem,
      quarantined: false,
    });

    this.record(key.id, "REGISTERED", at);
  }

  sign(
    keyId: string,
    purpose: TrustKey["purpose"],
    payload: unknown,
    at: string,
  ): string {
    const managed = this.keys.get(keyId);

    invariant(
      managed !== undefined,
      "KEY_NOT_REGISTERED",
      `Key ${keyId} is not registered`,
    );

    invariant(
      !managed.quarantined,
      "KEY_QUARANTINED",
      `Key ${keyId} is quarantined`,
    );

    invariant(
      managed.key.status === "active",
      "KEY_NOT_ACTIVE",
      `Key ${keyId} is not active`,
    );

    invariant(
      managed.key.purpose === purpose,
      "KEY_PURPOSE_MISMATCH",
      `Key ${keyId} cannot perform purpose ${purpose}`,
    );

    invariant(
      at >= managed.key.notBefore,
      "KEY_NOT_YET_VALID",
      `Key ${keyId} is not yet valid`,
    );

    invariant(
      managed.key.notAfter === undefined || at < managed.key.notAfter,
      "KEY_EXPIRED",
      `Key ${keyId} has expired`,
    );

    const signature = signCanonical(payload, managed.privateKeyPem);

    this.record(keyId, "USED_FOR_SIGNING", at);

    return signature;
  }

  verifyPrivateKeyBinding(
    keyId: string,
    payload: unknown,
    signature: string,
  ): boolean {
    const managed = this.keys.get(keyId);

    if (!managed || managed.quarantined) {
      return false;
    }

    return verifyCanonical(
      payload,
      signature,
      managed.key.publicKeyPem,
    );
  }

  /**
   * Read-only key-state verification.
   * Must not sign, mutate state, or append lifecycle events.
   */
  verifyKeyState(
    keyId: string,
    at: string,
    expectedPublicKeyPem?: string,
  ): boolean {
    const managed = this.keys.get(keyId);

    if (!managed || managed.quarantined) return false;
    if (managed.key.status !== "active") return false;
    if (at < managed.key.notBefore) return false;

    if (
      managed.key.notAfter !== undefined &&
      at >= managed.key.notAfter
    ) {
      return false;
    }

    if (
      expectedPublicKeyPem !== undefined &&
      managed.key.publicKeyPem !== expectedPublicKeyPem
    ) {
      return false;
    }

    return true;
  }

  quarantine(
    keyId: string,
    at: string,
    reason: string,
  ): void {
    const managed = this.keys.get(keyId);

    invariant(
      managed !== undefined,
      "KEY_NOT_REGISTERED",
      `Key ${keyId} is not registered`,
    );

    managed.quarantined = true;
    managed.key.status = "suspended";

    this.record(keyId, "QUARANTINED", at, reason);
  }

  revoke(
    keyId: string,
    at: string,
    reason: string,
  ): void {
    const managed = this.keys.get(keyId);

    invariant(
      managed !== undefined,
      "KEY_NOT_REGISTERED",
      `Key ${keyId} is not registered`,
    );

    managed.key.status = "revoked";

    this.record(keyId, "REVOKED", at, reason);
  }

  retire(
    keyId: string,
    at: string,
    reason: string,
  ): void {
    const managed = this.keys.get(keyId);

    invariant(
      managed !== undefined,
      "KEY_NOT_REGISTERED",
      `Key ${keyId} is not registered`,
    );

    managed.key.status = "expired";
    managed.key.notAfter = at;

    this.record(keyId, "RETIRED", at, reason);
  }

  getPublicKey(keyId: string): TrustKey {
    const managed = this.keys.get(keyId);

    invariant(
      managed !== undefined,
      "KEY_NOT_REGISTERED",
      `Key ${keyId} is not registered`,
    );

    return structuredClone(managed.key);
  }

  hasPrivateMaterial(keyId: string): boolean {
    return this.keys.has(keyId);
  }

  lifecycleEvents(): readonly KeyLifecycleRecord[] {
    return this.lifecycle.map((event) => structuredClone(event));
  }

  private record(
    keyId: string,
    event: KeyLifecycleEvent,
    at: string,
    reason?: string,
  ): void {
    this.lifecycle.push({
      sequence: ++this.sequence,
      keyId,
      event,
      at,
      ...(reason === undefined ? {} : { reason }),
    });
  }
}
