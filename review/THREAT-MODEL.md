# GIIA MVP 1.0 Threat Model

## Objective

Determine whether an attacker can obtain, alter, replay, forge, or misuse
authorization by defeating identity, authority, trust, provenance,
governance, constitutional, evidence, or enforcement boundaries.

## Assets

Primary assets:

- identity integrity
- credential integrity
- authority integrity
- delegation integrity
- authorization integrity
- provenance integrity
- governance signing authority
- constitutional integrity
- evidence integrity
- audit integrity
- replay state
- decision integrity
- execution authorization

## Threat Actors

### T1: Unauthenticated Attacker

Attempts to submit malformed or unauthorized requests.

Goals:

- obtain ALLOW
- bypass identity
- bypass authorization
- bypass policy
- cause unauthorized execution

### T2: Compromised Credential Holder

Possesses a legitimate but compromised identity or credential.

Goals:

- exceed permitted authority
- perform unauthorized actions
- substitute credentials
- exploit delegation

### T3: Compromised Agent

A trusted or previously registered agent behaves outside its permitted
capabilities.

Goals:

- capability escalation
- identity substitution
- provenance manipulation
- unauthorized delegation

### T4: Malicious or Compromised Governance Member

Controls one or more governance signing identities.

Goals:

- forge governance authority
- bypass quorum
- approve prohibited actions
- weaken constitutional protections

The system must assume that individual governance members can be compromised.

### T5: Malicious External Executor

Attempts to treat a GIIA artifact as authority without performing required
independent verification.

Goals:

- execute without valid authorization
- execute tampered decisions
- bypass GIIA restrictions

The architecture therefore requires independent verification at the external
execution boundary.

### T6: Insider With Local Access

Can inspect or manipulate files, runtime state, or development artifacts.

Goals:

- substitute keys
- alter evidence
- alter replay state
- modify configuration
- bypass trust bindings

The reviewer should determine which local-access assumptions are inside or
outside the deployment trust boundary.

## Attack Classes

### Identity Attacks

- identity substitution
- issuer substitution
- operator substitution
- owner substitution
- stale identity
- revoked identity

### Credential Attacks

- credential substitution
- credential replay
- credential expiration bypass
- credential revocation bypass
- unauthorized credential escalation

### Authority Attacks

- authority substitution
- delegation substitution
- delegation escalation
- insufficient authority presented as sufficient authority

### Governance Attacks

- one-of-five quorum attempt
- two-of-five quorum attempt
- duplicate signer
- revoked signer
- expired signer
- quarantined signer
- substituted signer
- signature mismatch
- authority certificate mismatch

### Provenance Attacks

- evidence substitution
- provenance substitution
- issuer substitution
- origin manipulation
- deployment-context manipulation
- declared capability escalation

### Policy Attacks

- policy substitution
- jurisdiction manipulation
- action-class substitution
- target substitution
- harm-risk manipulation
- prohibition bypass

### Decision Attacks

- decision tampering
- payload substitution
- request substitution
- stale decision
- expired decision
- replay
- cross-context reuse

### Constitutional Attacks

- unauthorized amendment
- AI approval
- wrong human approver
- wrong authority
- revoked approval
- expired approval
- amendment replay
- amendment tampering
- constitutional downgrade

### Execution Attacks

- execute without GIIA ALLOW
- execute using altered ALLOW
- execute using expired ALLOW
- execute using revoked authorization
- execute after shutdown
- execute without human approval
- bypass independent verification

## Security Properties to Verify

The reviewer should attempt to establish that:

1. Invalid identity cannot become valid identity through caller-controlled data.
2. Invalid credentials cannot become valid authorization.
3. Insufficient governance cannot become quorum.
4. Invalid provenance cannot become verified provenance.
5. Declared capabilities cannot become permitted capabilities automatically.
6. Tampered decisions cannot pass independent verification.
7. Replayed decisions cannot bypass durable replay protection.
8. Constitutional protections cannot be silently weakened.
9. AI cannot independently authorize constitutional changes.
10. GIIA ALLOW cannot directly execute a consequential operation.
11. External execution requires independent verification.
12. Security-critical failures remain fail-closed.

## Residual Risks

Passing the MVP tests does not establish that the implementation is free of
unknown vulnerabilities.

Important residual risks include:

- implementation defects not covered by existing tests
- dependency vulnerabilities
- host operating-system compromise
- compromised hardware
- insecure production key ceremony
- incorrect HSM integration
- insecure deployment configuration
- external executor compromise
- operational mistakes
- jurisdiction-specific legal requirements
- undiscovered cryptographic or protocol weaknesses

These risks require continued review and deployment hardening.
