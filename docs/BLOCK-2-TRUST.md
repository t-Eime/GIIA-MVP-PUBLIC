# GIIA Block 2: Trust Infrastructure

## Trust chain

Root → Anchor → Delegation → Credential

## Cryptography

- Ed25519 signatures
- Canonical signed payloads
- Public-key verification
- SHA-256 fingerprints

## Lifecycle

Trust keys support:

- active
- suspended
- revoked
- expired
- unknown

Rotation expires the previous key and creates a new active key.

## Revocation

Revocation is first-class and attributable:

- object type
- object ID
- revocation time
- reason
- authority
- provenance

## Durable storage

SQLite-backed TrustRegistry stores:

- keys
- roots
- anchors
- delegations
- credentials
- revocations
- replay records

## Security properties tested

- forged signatures
- subject substitution
- root binding substitution
- signing-key substitution
- wrong public keys
- delegation issuer substitution
- credential issuer substitution
- expiry
- revoked-key rejection
- key rotation
- durable persistence
- replay protection

## Canonical chain

Root → Anchor → Delegation → Credential → Authority → Authorization → Action → Evidence → Audit → Revocation
