# GIIA FOAE-01: Verifiable Producer Origin Foundation

## Scope

FOAE-01 establishes a cross-cutting producer-origin verification layer without creating a sixth GIIA core function.

## Reused GIIA foundations

- Identity
- Authority
- Authorization
- Trust
- Authenticated Verification
- Evidence and Evidence Chains

## Security boundary

A producer claim does not establish producer origin by itself.

A caller-supplied verification status does not establish verification.

Authenticated verification evidence must identify an authenticated and authorized verifier and bind the verification to the claimed producer.

Artifact-origin evidence must bind the artifact identity to its original artifact hash.

## Status semantics

`VERIFIED` means the required FOAE verification inputs passed.

It does not mean:

- universally trusted
- safe
- legally compliant
- authorized for every action
- free of future compromise
- permanently trusted

`REVOKED`, `EXPIRED`, `CONTRADICTED`, and `UNVERIFIABLE` remain distinct outcomes.

## Acceptance requirement

FOAE-01 is incomplete until:

1. TypeScript build passes.
2. Full test suite passes.
3. FOAE attack tests pass.
4. Existing trust/authentication tests remain passing.
5. No existing security boundary is weakened.
6. The final commit contains implementation, tests, and documentation.
