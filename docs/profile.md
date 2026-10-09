# Draft safety-evidence attestation profile

Status: demonstrator, not an accepted OpenSSF or in-toto standard.

## Purpose

The profile authenticates and transports a claim about an externally authored SRAC/SPDX safety-evidence graph. It does not create the graph, approve a safety decision, or determine that a safety claim is true.

The in-toto Statement binds:

- the software/product subject and SHA-256 digest;
- an exact-byte SHA-256 digest of the referenced decision/evidence closure graph;
- the analysis-root and trigger identifiers;
- the graph's declared closure state;
- an authorization authority and decision identifier.

The exact-byte artifact digest deliberately avoids claiming a cross-serialization semantic canonicalization rule. A future standards profile may replace this with an agreed SPDX graph canonicalization mechanism.

## Verification contract

Verification is intentionally layered:

1. **Envelope signature** — verify the DSSE signature using a known key.
2. **Artifact and subject binding** — verify the referenced graph digest and ensure the Statement subject, analysis root, trigger, and closure declaration match the graph.
3. **Graph completeness** — resolve every required decision, evidence, and verification edge and ensure every evaluated element has a closure decision.
4. **Authorization policy** — confirm the valid signing key is authorized for the claimed authority and that the authorization decision is accepted.
5. **Safety-claim truth** — always `not-evaluated`; this remains with the authoritative safety lifecycle and its reviewers.

`policyEligible=true` therefore means that the signed evidence satisfies the relying party's mechanical acceptance policy. It does not mean the verifier independently established the truth of the safety conclusion.

## DSSE

Fixtures use an in-toto Statement v1 serialized as the DSSE payload type `application/vnd.in-toto+json`. Signatures use Ed25519 and the standard DSSE pre-authentication encoding:

```text
DSSEv1 SP <len(payloadType)> SP <payloadType> SP <len(payload)> SP <payload>
```

The keys committed through the deterministic fixture generator are test keys only and must never be used for production evidence.

## Closure rules in this demonstrator

- The graph must declare `complete`.
- The analysis trigger must resolve.
- Every evaluated element must be covered by an accepted decision.
- A normal approval decision must resolve its required evidence and verification edges.
- Evidence must carry a SHA-256 digest and provenance reference.
- Required verification results must be `pass`.
- A justified `noAction` decision may close without additional evidence only when the relying-party policy explicitly permits it.

These rules are a testable proposal for discussion, not a replacement for the SPDX FunctionalSafety vocabulary or an organization's safety process.
