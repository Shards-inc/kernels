# KERNELS Specification Index

This directory is the **normative definition** of KERNELS.

## Reading Order

Read in this order for complete understanding:

### Core Specifications

| Order | Document | Content |
|-------|----------|---------|
| 1 | [SPEC.md](SPEC.md) | Invariants + mandatory behaviour |
| 2 | [GLOSSARY.md](GLOSSARY.md) | Terms are binding |
| 3 | [STATES.md](STATES.md) | State machine + transitions |
| 4 | [JURISDICTION.md](JURISDICTION.md) | Policy + deny/allow rules |
| 5 | [AUDIT.md](AUDIT.md) | Ledger schema, hash chaining, evidence bundle |
| 6 | [ERROR_MODEL.md](ERROR_MODEL.md) | Failure semantics (fail-closed) |
| 7 | [VARIANTS.md](VARIANTS.md) | Posture variants (must preserve invariants) |

### Extended Specifications

| Order | Document | Content |
|-------|----------|---------|
| 8 | [PLANES.md](PLANES.md) | Four planes architecture (governance, execution, perception, ops) |
| 9 | [PROPOSAL.md](PROPOSAL.md) | Structured proposal schema (eliminates ambiguity) |
| 10 | [PERMITS.md](PERMITS.md) | Permit token format and verification |
| 11 | [PERMIT_TOKENS.md](PERMIT_TOKENS.md) | HMAC-based permit token implementation (v0.2.0+) |
| 12 | [EVIDENCE.md](EVIDENCE.md) | Evidence packet schema and sensor types |

## Authority

Implementation lives in `/kernels`. If docs and spec conflict, **spec wins**.

## Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in specification documents are to be interpreted as described in RFC 2119.

## Specification Versioning

Each specification document includes its own version number. The overall specification version is determined by the highest version among all documents.

| Document | Version |
|----------|---------|
| SPEC.md | 0.1.0 |
| PLANES.md | 0.1.0 |
| PROPOSAL.md | 0.1.0 |
| PERMITS.md | 0.1.0 |
| PERMIT_TOKENS.md | 0.2.0-dev |
| EVIDENCE.md | 0.1.0 |
