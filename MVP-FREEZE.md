# GIIA MVP v0.1.0

## Status

**FROZEN**

The GIIA MVP has completed its defined validation scope.

### Validation

- Full regression: 387/387 PASS
- End-to-end authorization → independent execution: PASS
- Revocation enforcement: PASS
- Durable replay persistence: PASS
- Signed decision verification: PASS
- Independent executor boundary: PASS
- Agent Passport verification: PASS
- Capability enforcement: PASS
- Human approval enforcement: PASS
- Terminal shutdown enforcement: PASS
- Expiry enforcement: PASS
- Payload integrity enforcement: PASS
- Authorization binding enforcement: PASS
- Replay protection: PASS
- Tampered decision rejection: PASS
- Tampered payload rejection: PASS
- Wrong executor passport rejection: PASS

## Architectural freeze

The following boundaries are frozen for MVP:

1. GIIA does not execute operational work.
2. GIIA does not become the external executor.
3. External executors cannot become GIIA.
4. Agent identity is separate from the human actor identity represented in a GIIA decision.
5. Agent Passports are independently verified.
6. Authorization requires the required identity, authority, provenance, capability,
   integrity, expiry, human approval, revocation, and shutdown conditions.
7. GIIA execution authority remains NONE.
8. Fail-closed behavior remains mandatory.
9. Constitutional and governance protections cannot be weakened to satisfy tests.
10. MVP security invariants must not be removed for convenience.

## Freeze rule

New functionality belongs in Post-MVP/V1 unless it fixes a demonstrated
security defect in the frozen MVP.

Any MVP security defect discovered after freeze must be:
- documented,
- reproduced with a regression test,
- fixed without weakening an existing invariant,
- revalidated against the complete regression suite.

