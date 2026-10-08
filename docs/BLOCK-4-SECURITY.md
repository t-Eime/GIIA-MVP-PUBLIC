# GIIA Block 4 Security

## Status

Block 4 security hardening is in progress.

## Implemented

### Key Security Boundary

`KeySecurityBoundary` provides the controlled signing boundary for trust keys.

It enforces:

- key registration before signing
- active-key requirement
- private/public key cryptographic binding
- key-purpose enforcement
- not-before enforcement
- expiry enforcement
- revocation enforcement
- quarantine enforcement
- retirement
- lifecycle event recording
- controlled access to private signing material

Private key material is held in memory by the current implementation.

This implementation does not claim hardware-backed key protection, secure-element storage, TEE protection, or OS-keystore protection.

Platform-specific secure storage can be implemented behind this boundary in a later hardening stage.

## Trust Signing Path

Trust object issuance uses the security boundary:

- Root key signs Anchor
- Anchor key signs Delegation
- Delegation key signs Credential

The signing boundary validates the actual registered key purpose and lifecycle state before signing.

## Private/Public Key Binding

A private key cannot be registered against an unrelated public key.

Registration performs an Ed25519 signing and verification probe using the supplied private and public key material.

A mismatch is rejected.

## Legacy Signing Bypass Removed

The previous raw-private-key trust issuance functions were removed:

- `createAnchor`
- `createDelegation`
- `createCredential`

Trust tests were migrated to the controlled security boundary.

No raw-Pem trust issuance calls remain in `src` or `tests`.

## Security Tests

The security test suite covers:

- private/public key substitution
- signer purpose mismatch
- revoked signer
- quarantined signer
- expired signer
- unregistered signer
- incorrect registered key purpose
- trust-signing lifecycle enforcement
- existing trust-chain integrity
- signature forgery and substitution attacks

## Current Security Boundary

The following distinction is intentional:

Verification of an externally supplied signature establishes cryptographic validity.

Issuance of new trust objects requires the controlled signing boundary.

Cryptographic verification does not by itself claim that private signing material is hardware protected.

## Remaining Block 4 Work

The remaining Block 4 security and resilience work includes:

1. anti-replay hardening
2. tamper detection
3. compromise detection
4. compromise containment
5. recovery procedures
6. offline-state handling
7. degraded-operation handling
8. compromised-state handling
9. recovery-state handling
10. reconciliation
11. crash recovery
12. corruption recovery
13. controlled restart
14. human final verification before consequential authority is restored
15. security and recovery attack testing
16. persistence and recovery testing

## Controlled Restart Invariant

Recovery, repair, shutdown, safe-state transition, or restoration to a baseline state must not automatically restore consequential authority.

Return to operation requires:

1. recovery
2. integrity verification
3. safety verification
4. human or independently authorized external verification
5. recorded restart authorization

A factory or baseline restoration alone is insufficient.

## Acceptance Principle

Block 4 is not complete merely because cryptographic functions work.

Completion requires demonstrated resistance to relevant attacks and demonstrated safe behavior across failure, compromise, offline, recovery, reconciliation, and restart states.
