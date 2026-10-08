# GIIA MVP 1.0 Limitations

This document deliberately states what the MVP does not prove.

## 1. No Claim of Perfect Security

477 passing tests demonstrate that the tested behaviors passed.

They do not prove the absence of vulnerabilities.

Independent adversarial review remains necessary.

## 2. No Production HSM Deployment Claim

The MVP establishes the production secure-signing boundary and fails closed
when the required secure provider is unavailable.

Actual production HSM deployment, key ceremony, hardware protection,
operational controls, and provider integration remain deployment concerns.

## 3. Software Governance Implementation

The MVP includes a 3-of-5 governance multisignature implementation.

The production security posture requires appropriate operational protection
of governance signing keys.

## 4. No Consequential Execution

The MVP does not provide autonomous consequential execution.

GIIA evaluation produces an authorization artifact.

A separate external executor must independently verify the authorization
before consequential execution.

## 5. No Government Certification

The MVP does not claim certification, accreditation, approval, endorsement,
or deployment by any government or regulator.

## 6. No Independent Security Certification

The MVP has not been represented as independently certified merely because
its internal test suite passes.

External security assessment is still required.

## 7. No Universal Legal Compliance Claim

GIIA provides a jurisdiction-aware governance architecture.

It does not automatically guarantee legal compliance with every country's
laws, regulations, court orders, sector rules, or institutional policies.

## 8. External Systems Remain Separate Trust Domains

External operational systems may be governed through
GIIA interfaces.

They are not automatically part of the GIIA MVP simply because an
integration architecture exists.

Each external system requires its own security review.

## 9. External Executor Risk

An external executor can introduce vulnerabilities outside the GIIA MVP.

Independent verification reduces this risk but does not make a compromised
executor harmless.

## 10. Host and Hardware Risk

The MVP does not prove protection against:

- compromised operating systems
- compromised hardware
- kernel-level attackers
- malicious firmware
- physical extraction
- supply-chain compromise

These require deployment-specific controls.

## 11. Dependency Risk

Third-party dependencies may contain vulnerabilities that are not discovered
by the MVP test suite.

Dependency management and vulnerability monitoring remain required.

## 12. Operational Risk

Secure architecture can still be defeated by:

- incorrect configuration
- poor key management
- unsafe deployment
- weak access controls
- inadequate monitoring
- poor incident response
- incorrect governance procedures

Operational security is part of the eventual production system.

## 13. Review Is Part of the Product Process

The MVP should be treated as a frozen security baseline.

Independent review, adversarial testing, deployment hardening, and future
versioned changes must build on evidence rather than weaken the established
security invariants.
