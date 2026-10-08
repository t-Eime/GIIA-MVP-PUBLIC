# GIIA MVP 1.0 Review Guide

## 1. Establish the Release

Verify:

    git describe --tags --exact-match HEAD

Expected:

    giia-mvp-1.0.0

Verify:

    git rev-parse HEAD

Expected:

    3c7c8385bccb25c084ee80c3b45644676ba876f5

## 2. Reproduce the Build

Run:

    npm install
    npm run build
    npm test

Expected:

    477 tests
    477 pass
    0 fail

Do not modify the frozen release while reproducing it.

## 3. Understand the Authorization Pipeline

The conceptual pipeline is:

Request
→ Normalization
→ Identity
→ Credential
→ Trust
→ Authority
→ Delegation
→ Authorization
→ Jurisdiction
→ Policy
→ Action Class
→ Target
→ Harm Risk
→ Prohibition
→ Assurance
→ Decision
→ Enforcement
→ Evidence
→ Audit Commit

The review should determine whether any stage can be bypassed or falsified.

## 4. Test ALLOW

Identify a valid request that satisfies all required trust,
authorization, governance, policy, jurisdiction, provenance, and assurance
requirements.

Verify that GIIA can produce a valid ALLOW decision.

Then verify that the ALLOW decision does not itself execute the operation.

## 5. Test DENY

Modify one security-critical condition at a time.

Examples:

- invalid identity
- invalid credential
- expired credential
- revoked credential
- invalid authority
- insufficient governance quorum
- invalid provenance
- prohibited action
- invalid jurisdiction
- expired decision
- terminal shutdown
- missing human approval

Verify that the resulting request cannot become ALLOW.

## 6. Attack Decision Integrity

Attempt to modify:

- decision
- request
- action
- target
- authorization
- credential
- evidence
- governance authority
- provenance

The verifier must reject tampered material.

## 7. Attack Governance

The production governance boundary requires 3-of-5 authority.

Attempt:

- one signer
- two signers
- duplicate signer
- revoked signer
- expired signer
- quarantined signer
- substituted signer
- mismatched authority certificate

None should create valid production governance authority.

## 8. Attack Agent Trust

Attempt to substitute:

- agent identity
- operator
- owner
- issuer
- passport
- declared capability
- permitted capability
- deployment environment

Declared capability alone must not become authorization.

## 9. Attack Replay

Attempt to replay a valid decision.

Test:

- same request
- same decision
- restart
- concurrent consumption
- stale decision
- already-consumed decision

Replay protection must remain effective across restart.

## 10. Attack Constitutional Protection

Attempt:

- unauthorized amendment
- AI-generated approval
- wrong human approval
- wrong authority
- revoked approval
- expired approval
- amendment tampering
- replayed amendment
- constitutional downgrade

The constitutional protection must fail closed.

## 11. Examine the Execution Boundary

Confirm:

- GIIA creates an ActionIntent
- GIIA does not create an execution ActionRecord
- no consequential execution endpoint exists in the MVP
- an external executor independently verifies GIIA authorization
- tampered or invalid decisions cannot authorize execution

## 12. Report Findings

For every finding provide:

- exact release commit
- affected component
- reproduction steps
- expected behavior
- actual behavior
- security impact
- whether exploitation requires privileged access
- minimal proof of concept
- recommended remediation

Do not modify the frozen release when reproducing a finding.
Create a separate working branch for experiments.
