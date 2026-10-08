# GIIA MVP 1.0 External Review Package

GIIA is Global Identity, Authority, Trust & Governance Infrastructure.

GIIA does not perform the work.
GIIA determines whether the work is authorized to occur.

This review package provides the material required for independent technical,
security, architecture, and adversarial review of the GIIA MVP 1.0 release.

## Frozen Release

Release tag:

    giia-mvp-1.0.0

Release commit:

    3c7c8385bccb25c084ee80c3b45644676ba876f5

Expected verification:

    477 tests
    477 pass
    0 fail
    0 skipped
    0 todo

## Reproduce

    git checkout giia-mvp-1.0.0
    npm install
    npm run build
    npm test

The reviewer should independently verify the release commit and test results.

## Review Objective

The objective is not to demonstrate that the system works only under
expected conditions.

The objective is to determine whether the security and governance boundaries
can be bypassed.

Reviewers are specifically encouraged to attempt:

- decision tampering
- payload substitution
- evidence substitution
- governance-key substitution
- signer substitution
- quorum reduction
- revoked signer use
- expired signer use
- quarantined signer use
- credential substitution
- capability escalation
- agent/passport substitution
- provenance manipulation
- jurisdiction manipulation
- replay
- stale decision reuse
- constitutional downgrade
- unauthorized constitutional amendment
- AI constitutional approval
- human approval substitution
- bypass of independent verification
- execution without valid GIIA authorization

## Important Boundary

The MVP does not execute consequential external operations.

GIIA evaluation produces an authorization decision and evidence.

An external executor must independently verify the GIIA decision before
performing a consequential operation.

Therefore a successful GIIA evaluation must not be interpreted as direct
execution authority.

## Security Review Standard

A passing test suite is evidence of implemented behavior.

It is not proof that the implementation contains no vulnerabilities.

Reviewers should treat all security claims as hypotheses to be challenged.

## Known Production Boundary

The MVP contains a software implementation of governance multisignature
authority.

Production deployment requires an appropriate secure signing provider/HSM
and operational key-management controls.

The MVP does not claim that production HSM infrastructure is deployed.

## Review Principle

Try to break the trust boundary.

If a reviewer discovers a way to transform an invalid request, identity,
credential, authority, provenance record, governance decision, or approval
into an accepted consequential action, that finding is highly significant.
