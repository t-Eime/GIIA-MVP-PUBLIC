# GIIA Block 3: Governance + Constitutional Layer

## Global constitutional core

The GIIA constitutional core is jurisdiction-neutral.

It does not hard-code:

- countries
- regulators
- police agencies
- courts
- sovereign institutions
- national reporting destinations
- national legal systems

Jurisdiction-specific rules are represented as governed constitutional overlays.

## Decision states

The constitutional engine preserves:

- ALLOW
- DENY
- DEFER

Unverified or unavailable constitutional authority fails closed to DEFER rather than silently granting authority.

## Rule lifecycle

Rules support:

- active
- suspended
- revoked
- expired
- unknown

Rules are versioned and time-bounded.

## Signed governance

Constitutional rules use Ed25519 signatures over canonical payloads.

A modified signed rule fails verification.

## Precedence

Rules are resolved using:

1. precedence
2. scope specificity
3. deterministic rule ID ordering

Conflicting rules at equal precedence and specificity produce DEFER.

## Jurisdiction

Global rules remain applicable across jurisdictions unless a jurisdiction-specific rule governs the action.

Jurisdictional rules require an explicit jurisdiction identifier.

## Durable registry

SQLite stores:

- constitutional rules
- revocations
- replay records

## Security properties

Tested:

- prohibition
- missing conditions
- expiry
- revocation
- jurisdiction isolation
- precedence
- specificity
- policy conflict
- signature forgery
- verified-rule fail-closed behavior
- durable persistence
- replay protection
