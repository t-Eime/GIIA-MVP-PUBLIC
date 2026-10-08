# GIIA FOAE Gap Analysis

Specification: GIIA-FOAE-001
Status: Engineering Gap Analysis
Scope: Global GIIA Core

## 1. Purpose

Identify the minimum architectural gaps required to implement
GIIA Verifiable Origin, Authority & Evidence Foundation (FOAE)
without creating a new core pillar, duplicating existing capabilities,
or weakening existing trust/security boundaries.

## 2. Existing Capability Ownership

| Capability | Existing Owner | Status |
|---|---|---|
| Identity | src/identity | Existing |
| Authority | src/authority | Existing |
| Authorization | src/authorization | Existing |
| Evidence | src/evidence | Existing |
| Provenance | Identity/Authority/Evidence/Trust | Distributed |
| Cryptographic Trust | src/trust | Existing |
| Credentials | src/trust | Existing |
| Delegation | src/trust | Existing |
| Revocation | Trust/Constitution/Security | Existing |
| Verification | src/trust/verification.ts | Existing, hardened |
| Audit | src/audit | Existing |
| Governance | src/governance + Constitution | Existing |
| Resilience/Recovery | src/resilience | Existing |
| Security/Containment | src/security | Existing |

## 3. FOAE Gaps

### 3.1 Organization-Origin Recognition

Required capability:
- Recognize an organization as the authentic original producer,
  owner, issuer, or declarant of an artifact.
- Bind recognition to independently verifiable evidence.
- Preserve issuer, provenance, validity, scope, and revocation data.

Must NOT:
- establish general trustworthiness automatically
- establish product safety automatically
- establish legal compliance automatically
- establish authorization for unrelated actions

Owner:
- Existing Identity + Trust + Evidence capabilities.
- New FOAE evidence types only where required.

### 3.2 Producer Certificate / Artifact Verification

Required capability:
- Preserve/reference authentic producer-issued artifacts.
- Preserve cryptographic hash/signature.
- Bind issuer and authorized issuing authority.
- Preserve publication/declaration status.
- Preserve validity, revocation, scope, conditions, and assurance terms.
- Distinguish original artifact from GIIA verification evidence.

Must NOT:
- make GIIA the original issuer
- silently modify the producer artifact.

Owner:
- Trust + Evidence + Provenance.

### 3.3 Producer Assurance / Liability Evidence

Required capability:
- Record authenticated producer commitments.
- Preserve exact scope, terms, limitations, exclusions,
  provenance, and effective period.
- Distinguish producer commitment from technical verification.

Must NOT:
- treat liability as proof of safety, authenticity,
  authorization, or general trust.

Owner:
- Evidence + Governance.

### 3.4 Cross-Examination / Verification Analysis

Required capability:
- Examine claimed issuer.
- Examine organization identity.
- Examine issuer authority.
- Verify signatures and integrity.
- Verify provenance and publication status.
- Check validity and revocation.
- Check scope and applicable requirements.
- Detect contradictions.
- Record observations separately from claims.
- Produce a verification result with evidence references.

Must NOT:
- convert analysis into authorization.
- treat absence of contradiction as proof of truth.
- allow AI recommendation to become authority.

Owner:
- Evidence + Verification + Governance.

### 3.5 Authority Visibility

Required capability:
Display, where verifiable:
- current recognized authority holder
- role
- authority ID
- status
- scope
- validity period
- issuer
- supporting evidence
- revocation status
- last verification
- delegation chain

When unverifiable:
- display UNKNOWN or DISPUTED.
- preserve the last authenticated authority.
- never invent an authority holder.

Owner:
- Authority + Evidence + Verification.

### 3.6 Management Authority Examination

Required capability:
- Identify controlling management authority.
- Verify management authority identity.
- Verify who authorized that authority.
- Verify ownership/management relationship.
- Verify exact policy and scope.
- Verify validity and revocation.
- Preserve evidence for disputes.

Must NOT:
- bypass a platform administrator merely because a user requests it.
- declare either side correct when authority is unverifiable.

Owner:
- Authority + Authorization + Evidence + Governance.

### 3.7 Pre-Deployment Verification

Required capability:
Before installation/deployment:
- verify artifact identity
- verify original producer
- verify provenance
- verify integrity
- verify applicable certificate/attestation
- verify validity/revocation
- verify authorization and applicable requirements

UNKNOWN, mismatch, revoked, or unauthorized artifacts must
not silently become trusted.

Owner:
- Verification + Trust + Evidence + Authorization.

### 3.8 Post-Deployment Verification

Required capability:
After deployment:
- verify installed artifact identity
- compare against authenticated original
- verify version/status
- detect unauthorized modification
- revalidate certificates/attestations
- preserve evidence
- support continuous/recurrent verification.

Loss of verifiability must not automatically restore authority.

Owner:
- Verification + Evidence + Security + Resilience.

### 3.9 Continuous Re-Verification

Current state:
- Partially represented by existing verification and revocation
  mechanisms.

Required hardening:
- Explicit distinction between historical verification and
  current trust status.
- Current revocation/status checks must not be inferred solely
  from historical evidence.

Owner:
- Trust + Verification + Security.

## 4. Anti-Circular-Trust Requirement

FOAE evidence must not authenticate itself.

A claim cannot establish:
- identity
- authenticity
- authority
- authorization
- provenance
- legitimacy
- compliance
- consequential permission

without independently verifiable evidence appropriate to the
required trust level.

## 5. Architectural Placement

FOAE is cross-cutting.

It does NOT create a sixth core function.

The five irreducible GIIA functions remain:

1. Identity
2. Authority
3. Authorization
4. Evidence & Provenance
5. Governance

## 6. Security Requirements

All FOAE implementation must preserve:

- Fail-closed verification.
- Claim-Evidence Separation.
- Trust Failure and Anomalous Artifact containment.
- Human Final Verification & Controlled Restart.
- Revocation-first behavior.
- Cryptographic integrity.
- Provenance preservation.
- No silent trust restoration.
- No AI-to-authority escalation.
- No unauthorized bypass of management authority.

## 7. Required Implementation Order

1. FOAE evidence/data model.
2. Organization-origin recognition.
3. Producer certificate/artifact verification.
4. Producer assurance/liability evidence.
5. Cross-examination/verification analysis.
6. Authority visibility.
7. Management-authority examination.
8. Pre-deployment verification.
9. Post-deployment verification.
10. Continuous/recurrent re-verification.
11. Attack testing.
12. Full integration testing.
13. Full-system acceptance.

## 8. Acceptance Rule

No FOAE block is complete because its local tests pass.

Acceptance requires:
- build
- unit tests
- integration tests
- attack tests
- failure/recovery tests
- regression tests
- verification of core invariants
- full GIIA test suite

Final acceptance remains whole-system proof.
