# GIIA MVP 1.0 Security Boundary

## Purpose

This document defines what GIIA is responsible for, what it is not
responsible for, and where security authority begins and ends.

## Core Principle

GIIA does not perform the work.

GIIA determines whether the work is authorized to occur.

A GIIA ALLOW decision is an authorization artifact. It is not, by itself,
permission for an external system to execute an operation without independent
verification.

## Trust Boundary

The MVP separates:

1. Requesting party
2. Identity
3. Credentials
4. Trust state
5. Authority
6. Delegation
7. Authorization
8. Jurisdiction
9. Policy
10. Action classification
11. Target
12. Harm assessment
13. Prohibitions
14. Assurance
15. Governance decision
16. Evidence
17. Audit
18. External execution

Security-sensitive facts must not be supplied solely by the caller when the
system is responsible for independently verifying those facts.

## Governance Boundary

The governance model requires 3-of-5 authority for the production boundary.

The implementation must reject:

- insufficient quorum
- duplicate signer participation
- revoked signers
- expired signers
- quarantined signers
- substituted signers
- mismatched authority certificates
- invalid governance signatures

A single compromised governance member must not create quorum.

Two compromised members must not create quorum.

## Signing Boundary

Production signing must use the configured secure signing boundary.

The production path must fail closed when the required secure provider is
unavailable.

The production path must not silently replace secure signing with a software
fallback.

The MVP therefore does not claim that production HSM infrastructure has
already been deployed.

## Identity and Credential Boundary

Identity is distinct from authority.

Credential possession is distinct from authorization.

A valid identity does not automatically grant authority.

A valid credential does not automatically authorize every action.

Expired, revoked, substituted, or otherwise invalid credentials must not
produce valid authorization.

## Agent Boundary

Agent identity and provenance are security inputs.

The trust boundary includes:

- agent identity
- operator
- owner
- issuer
- model or agent type
- lifecycle state
- declared capability
- permitted capability
- credential
- delegation
- deployment environment
- validity
- revocation

A declared capability is not equivalent to a permitted capability.

A claimed identity is not equivalent to verified identity.

A claimed provenance record is not equivalent to verified provenance.

## Constitutional Boundary

Constitutional protections are higher-order governance controls.

Constitutional amendments require the defined human approval and governance
requirements.

AI cannot independently approve constitutional changes.

Protected invariants cannot be weakened through an ordinary amendment path.

Unknown or malformed constitutional material must not weaken existing
protections.

## Evidence Boundary

Claims, evidence, and verification are separate concepts.

Evidence must have provenance.

Security-relevant evidence must be protected against unauthorized mutation.

Audit records must preserve the distinction between evaluation and execution.

## Execution Boundary

The MVP does not execute consequential external operations.

GIIA evaluation produces an ActionIntent rather than an execution
ActionRecord.

An external executor is responsible for consequential execution.

The external executor must independently verify the GIIA decision and all
required security bindings before execution.

This separation is intentional.

## Replay Boundary

A valid authorization artifact must not become indefinitely reusable.

Replay protection covers:

- repeated consumption
- restart
- concurrent consumption
- stale decisions
- already-consumed decisions

Durable state must preserve replay protections across process restart.

## Failure Model

Security-critical failures are fail-closed.

Examples include:

- invalid identity
- invalid credential
- insufficient authority
- failed provenance
- failed policy
- prohibited action
- invalid jurisdiction
- failed assurance
- invalid governance quorum
- invalid signature
- expired authorization
- revoked authorization
- terminal shutdown
- missing required human approval
- tampered evidence

Failure must not silently convert into ALLOW.

## Out of Scope for MVP

The MVP does not claim to provide:

- deployed HSM infrastructure
- autonomous consequential execution
- government certification
- independent security certification
- proof of absence of implementation vulnerabilities
- universal legal compliance across every jurisdiction
- protection against every compromise of an external executor
- protection against compromised hardware or operating systems outside the
  defined trust boundary

These are deployment, assurance, integration, or future-hardening concerns.

## Reviewer's Primary Question

Can an attacker transform an invalid security state into an accepted
authorization or consequential execution?

That is the central boundary to attack.
