# GIIA Trust-to-Action Binding Contract

## Purpose

Define the governed path from verified trust to consequential action.

## Canonical Chain

Root
→ Anchor
→ Delegation
→ Credential
→ Authority
→ Authorization
→ Action
→ Evidence
→ Audit
→ Revocation

## Mandatory Invariants

1. A verified Trust Credential does not automatically equal Authority.
2. Every Authority must explicitly declare its supporting trustCredentialId.
3. The declared trustCredentialId must match the independently verified Trust Credential.
4. Authority must have an independently verifiable trust basis.
5. Authorization must validate the applicable Authority.
4. Revoked or expired trust material cannot support consequential authorization.
5. Authorization does not equal execution.
6. Consequential execution must produce attributable evidence.
7. Evidence must be integrity-verifiable.
8. Audit records must preserve authorization and evidence provenance.
9. AI or machine recommendation cannot create consequential authority.
10. Recovery or restart cannot silently restore consequential authority.
11. Unknown or unverifiable trust state fails closed.
12. Revocation must be checked before consequential authorization.
13. A mismatch between an Authority's declared trust credential and the verified credential must DENY.

## Non-Goals

This contract does not create:
- a global government authority;
- automatic legal legitimacy;
- autonomous AI authority;
- unrestricted execution;
- centralized global identity storage.

## Failure Rule

If the trust basis, authority, authorization, execution provenance,
evidence integrity, or revocation state cannot be established,
the consequential action must DENY, DEFER, CONTAIN, or require
authorized verification.

## Canonical 19-Stage Governance Pipeline

Every consequential request MUST pass through these stages in order:

1. Request
2. Normalization
3. Identity
4. Credential
5. Trust
6. Authority
7. Delegation
8. Authorization
9. Jurisdiction
10. Policy
11. Action Class
12. Target
13. Harm Risk
14. Prohibition
15. Assurance
16. Decision
17. Enforcement
18. Evidence
19. Audit Commit

### Stage Invariants

1. Every stage MUST receive an attributable input from the preceding governed stage.
2. A stage MUST NOT be considered satisfied merely because a caller supplies a claimed result for that stage.
3. Unknown, missing, malformed, unverifiable, expired, revoked, or contradictory consequential state MUST NOT silently become ALLOW.
4. Stage order MUST NOT be bypassed to obtain an authoritative consequential decision.
5. Lower-level service results are stage results, not authoritative consequential decisions.
6. Identity MUST NOT be treated as Authority.
7. Credential MUST NOT be treated as Authority.
8. Trust MUST NOT be treated as Authority.
9. Authority MUST have an independently verifiable trust basis.
10. Delegation MUST remain within the authority and scope actually granted.
11. Authorization MUST bind the identified subject, authority, action, and target.
12. Jurisdiction MUST be determined from governed jurisdictional context where applicable and MUST NOT be hard-coded into the global core.
13. Policy MUST be versioned, attributable, provenance-preserving, and evaluated as governed policy.
14. Action Class MUST identify the governed class of requested action.
15. Target MUST identify the consequential object, resource, entity, or scope affected by the action.
16. Harm Risk MUST be evaluated before consequential Decision.
17. Prohibition MUST be evaluated before consequential Decision.
18. Assurance MUST establish the required confidence, verification, and control conditions for the action class.
19. Decision MUST be produced by the authoritative governed boundary, not reconstructed from caller-supplied stage outputs.
20. Enforcement MUST NOT exceed the authority, authorization, policy, jurisdiction, and action scope established by preceding stages.
21. Evidence MUST be attributable to the request, decision, action, actor, and relevant governed inputs.
22. Audit Commit MUST preserve the provenance and integrity of the consequential decision and its evidence.
23. Authorization MUST NOT be treated as execution.
24. Evidence MUST NOT be treated as authority.
25. Audit MUST NOT be used to retroactively create authority.
26. AI or machine recommendations MUST NOT create or expand authority.
27. Recovery, restart, reconciliation, or integrity repair MUST NOT silently restore consequential authority.
28. Revocation MUST be checked before consequential authorization and consequential Decision.
29. Constitutional or governance verification MUST be performed by GIIA's governed verification path; caller-supplied verification claims MUST NOT establish constitutional authority.
30. Only the complete governed pipeline MAY produce an authoritative consequential ALLOW.

## Authoritative Decision Boundary

`evaluateCoreRequest()` and other lower-level services are primitives.

A lower-level `ALLOW` MUST NOT be interpreted as an authoritative consequential decision.

The authoritative boundary MUST independently establish the required stages and construct the final Decision only after the complete governed pipeline has passed.

The authoritative boundary MUST NOT accept a caller-supplied `TrustToActionResult`, stage result, verification claim, or equivalent object and promote it into authoritative status.

## Constitutional and Governance Verification

Constitutional and governance rules are governed inputs.

Before an authoritative Decision can rely on a constitutional or governance rule:

1. The rule MUST be identified.
2. Its status and effective period MUST be verified.
3. Its provenance MUST be available.
4. Its issuer MUST be independently trusted.
5. Required constitutional/governance authority claims MUST be verified.
6. The rule's cryptographic integrity/signature MUST be verified where required.
7. The verified rule set MUST be produced by GIIA's own governed verification path.
8. A caller MUST NOT be able to manufacture an authoritative verified-rule list merely by supplying rule identifiers.

If required constitutional or governance authority cannot be verified, the consequential decision MUST fail closed according to the applicable failure semantics.

## Consequential ALLOW Rule

An authoritative consequential `ALLOW` exists only when:

- all required stages 1–19 have been evaluated in order;
- required inputs are attributable and integrity-verifiable;
- identity, credential, trust, authority, and delegation are valid;
- authorization is valid;
- applicable jurisdiction and policy are established;
- action class and target are established;
- harm risk and prohibitions have been evaluated;
- assurance requirements are satisfied;
- revocation and expiry checks have passed;
- the authoritative Decision is produced by GIIA itself;
- enforcement remains within established authority and scope;
- required evidence is created and integrity-verifiable; and
- Audit Commit preserves the complete provenance chain.

Otherwise, the result MUST be `DENY`, `DEFER`, `CONTAIN`, or require authorized human/external verification according to the governed failure semantics.

## Execution Boundary

GIIA establishes governed authority and decision provenance.

GIIA does not equate authorization with execution.

An external execution system MUST independently receive and enforce the authoritative decision and its applicable scope. Execution MUST produce attributable evidence that can be reconciled with the originating authorization and decision.

