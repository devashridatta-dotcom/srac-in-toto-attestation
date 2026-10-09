# SRAC in-toto safety-evidence attestation demonstrator

This repository provides a concrete, testable draft for the discussion in [OpenSSF Supply Chain Integrity issue #92](https://github.com/ossf/wg-supply-chain-integrity/issues/92).

It shows how a signed in-toto/DSSE envelope can bind a software subject to an externally authored SRAC/SPDX decision-and-evidence closure graph while keeping three questions separate:

1. Is the envelope authentic and unmodified?
2. Is the referenced safety-evidence graph complete and correctly bound?
3. Is the signer authorized under the relying party's policy?

The verifier **never determines that the underlying safety claim is true** and never creates or approves a safety decision.

> **Status:** independent demonstrator. This is not an accepted OpenSSF, in-toto, or SPDX standard.

## Flow

```text
Authoritative SRAC/SPDX decision graph
                 |
                 | exact-byte SHA-256 binding
                 v
          in-toto Statement v1
                 |
                 v
             DSSE envelope
                 |
       +---------+----------+
       |         |          |
       v         v          v
   signature   graph     authority
   validation  closure   policy
       \         |         /
        +--------+--------+
                 |
                 v
      policy eligibility result
      (safety truth not evaluated)
```

## Conformance fixtures

| Fixture | Signature | Binding | Graph | Authority | Eligible |
|---|---|---|---|---|---|
| `positive-complete-authorized` | Pass | Pass | Pass | Pass | Yes |
| `negative-incomplete-missing-evidence` | Pass | Pass | Fail | Not evaluated | No |
| `negative-complete-unauthorized` | Pass | Pass | Pass | Fail | No |
| `negative-cross-subject-substitution` | Pass | Fail | Not evaluated | Not evaluated | No |
| `positive-permitted-no-action` | Pass | Pass | Pass | Pass | Yes |

All negative fixtures are signed *after* their deliberate defect is constructed. Signature verification therefore passes where intended while the appropriate downstream verification layer rejects the claim.

## Run

```bash
go test ./...
python scripts/validate_schemas.py
go run ./cmd/srac-attest verify-suite \
  --fixtures fixtures \
  --policy policy/example-policy.json
```

Verify a single fixture:

```bash
go run ./cmd/srac-attest verify \
  --envelope fixtures/positive-complete-authorized/envelope.dsse.json \
  --bundle-dir fixtures/positive-complete-authorized \
  --policy policy/example-policy.json
```

Regenerate the deterministic test-only keys and signed fixtures:

```bash
go run ./cmd/srac-attest generate-fixtures \
  --output fixtures \
  --policy policy/example-policy.json
```

See [the draft profile](docs/profile.md) for the verification contract and limitations.

## Repository contents

- `schema/` — draft predicate and decision/evidence graph JSON Schemas
- `fixtures/` — signed positive and negative conformance examples
- `policy/` — example relying-party verification and authorization policy
- `cmd/srac-attest/` — fixture generator and verifier
- `internal/profile/` — DSSE, binding, completeness, and authorization implementation

## Security boundary

This project is a demonstrator and is not suitable for production key management. The checked-in fixture keys are deterministic and public. A production implementation would require managed identities, key rotation and revocation, trusted-time handling, policy distribution, audit logging, and an agreed SPDX/SRAC graph representation.
