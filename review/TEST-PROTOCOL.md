# GIIA MVP 1.0 External Test Protocol

## Baseline

Frozen release:

    giia-mvp-1.0.0

Commit:

    3c7c8385bccb25c084ee80c3b45644676ba876f5

Expected baseline:

    477 tests
    477 pass
    0 fail
    0 skipped
    0 todo

## Phase 1: Reproducibility

Run:

    git checkout giia-mvp-1.0.0
    git rev-parse HEAD
    npm install
    npm run build
    npm test

Record the exact output.

## Phase 2: Static Review

Inspect:

- authorization boundary
- governance signing
- trust verification
- provenance verification
- constitutional controls
- replay protection
- evidence integrity
- execution boundary

Search specifically for:

- fallback paths
- bypass conditions
- caller-controlled security facts
- unchecked assertions
- implicit trust
- mutable security state
- missing expiry checks
- missing revocation checks
- missing provenance checks
- execution paths

## Phase 3: Positive Tests

Confirm that valid inputs can produce:

- valid identity
- valid credentials
- valid authority
- valid delegation
- valid authorization
- valid governance decision
- valid evidence
- valid ALLOW result

Confirm that the resulting ALLOW remains an authorization result and not
direct consequential execution.

## Phase 4: Negative Tests

For each security property, modify exactly one relevant input.

Examples:

    identity
    credential
    authority
    delegation
    provenance
    jurisdiction
    policy
    action
    target
    harm risk
    prohibition
    assurance
    governance signer
    governance quorum
    human approval
    constitutional state

Expected result:

    DENY
    or
    verification failure

An invalid security state must not silently become ALLOW.

## Phase 5: Tamper Tests

Attempt to modify after issuance:

- request
- action
- target
- decision
- authorization
- evidence
- credential
- signer
- authority
- provenance

Verify that integrity checks detect the modification.

## Phase 6: Governance Tests

Attempt:

1. One signer.
2. Two signers.
3. Three valid signers.
4. Duplicate signer.
5. Revoked signer.
6. Expired signer.
7. Quarantined signer.
8. Substituted signer.
9. Incorrect authority certificate.

Expected:

- 1 signer: reject
- 2 signers: reject
- 3 valid signers: accept when all other requirements pass
- invalid signer conditions: reject

## Phase 7: Replay Tests

Perform:

1. valid authorization
2. consume authorization
3. repeat consumption
4. restart process
5. attempt consumption again
6. concurrent consumption
7. stale authorization

Expected:

Only the valid first consumption succeeds.

## Phase 8: Constitutional Tests

Attempt:

- unauthorized amendment
- missing human approval
- wrong human approval
- AI approval
- wrong governance authority
- revoked approval
- expired approval
- amendment replay
- amendment tampering
- downgrade of protected invariant
- weakening of fail-closed behavior

Expected:

All prohibited amendment paths fail.

## Phase 9: Execution Boundary Tests

Verify that:

- GIIA does not expose consequential execution as part of the MVP
- GIIA evaluation produces ActionIntent
- execution ActionRecord is not created by evaluation
- external executor verification is independent
- invalid or altered decisions are rejected by the executor

## Phase 10: Evidence Review

Confirm that security evidence records:

- preserve provenance
- resist unauthorized modification
- distinguish evaluation from execution
- preserve relevant audit history
- support replay and tamper investigation

## Phase 11: Findings

Classify findings by impact:

### Critical

Allows unauthorized consequential execution or governance takeover.

### High

Allows bypass of a major authorization, identity, provenance, governance,
or constitutional control.

### Medium

Weakens a security property without directly producing unauthorized
consequential execution.

### Low

Documentation, diagnostics, hardening, or defense-in-depth issue.

### Informational

Observation with no demonstrated security impact.

## Reproduction Standard

A valid finding should include:

- exact commit
- environment
- commands
- input
- expected result
- actual result
- logs or evidence
- security impact
- minimal reproduction

Do not modify the frozen release when reproducing baseline behavior.
