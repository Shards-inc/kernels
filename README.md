# KERNELS — Deterministic Control Planes for AI Systems

A **kernel** is a deterministic state machine that governs AI agent execution via **jurisdiction**, **fail-closed arbitration**, and an **append-only hash-chained audit ledger**.

**Hard constraint:** no tool execution without an explicit `ALLOW`; no `ALLOW` without a committed audit decision.

---

## Problem (Operational, Not Philosophical)

Ungoverned agent systems fail in predictable ways:

| Failure Mode | Consequence |
|--------------|-------------|
| Ambiguity escapes into execution | Actions occur without a crisp, auditable decision boundary |
| Implicit state drift | Post-hoc analysis becomes narrative, not replay |
| Tool reach exceeds operator intent | "Capability" becomes "authority" |
| Logs are advisory | Missing transitions = missing truth |
| Accountability diffuses | No single place to prove "why this happened" |

KERNELS exists to make those failure modes **structurally expensive** and **forensically obvious**.

---

## Model

```
OPERATOR (authority) ── KernelRequest ──▶ KERNEL (policy+state+audit) ──▶ TOOL REGISTRY
       ▲                                           │
       └───────────── KernelReceipt ◀──────────────┘

AGENT has no direct tool access; it submits requests and receives results.
```

Separation is the point:

| Component | Responsibility | Authority |
|-----------|----------------|-----------|
| Operator | Sets policy, reviews evidence, halts | Highest |
| Kernel | Validates, arbitrates, records | Delegated |
| Tool registry | Executes sanctioned ops | None |
| Agent | Requests + consumes results | None |

---

## Core Invariants (Normative)

A compliant kernel MUST satisfy:

| ID | Invariant | Description |
|----|-----------|-------------|
| INV-STATE | Single state | Exactly one state at any time |
| INV-TRANSITION | Explicit transitions | Transitions only via declared functions |
| INV-JURISDICTION | Policy enforcement | Every request passes policy before execution |
| INV-AUDIT | Audit completeness | Every transition emits an audit entry before completion |
| INV-HASH-CHAIN | Chain integrity | Audit entries chain to previous hash |
| INV-FAIL-CLOSED | Deny on ambiguity | Ambiguity/malformed/unhandled ⇒ `DENY` or `HALT` |
| INV-DETERMINISM | Reproducibility | Identical inputs + initial state ⇒ identical outputs |
| INV-HALT | Halt availability | Immediate halt from any state; terminal for session |
| INV-EVIDENCE | Exportability | Decisions exportable as verifiable evidence bundle |
| INV-NO-IMPLICIT-ALLOW | Explicit permission | "Not denied" ≠ allowed; explicit `ALLOW` required |

---

## State Machine (Canonical)

```
BOOTING → IDLE → VALIDATING → ARBITRATING → (EXECUTING)? → AUDITING → IDLE
                                                                      ↓
Any unhandled exception ────────────────────────────────────────▶ HALTED
```

---

## Public API (Supported Surface)

Treat everything else as internal. Your stable integration points:

```python
from kernels import (
    # Core types
    Kernel,              # Protocol / interface
    KernelRequest,       # Request structure
    KernelReceipt,       # Response structure
    Decision,            # ALLOW | DENY | HALT
    KernelConfig,        # Configuration
    
    # Variants
    StrictKernel,        # Maximum enforcement
    PermissiveKernel,    # Relaxed thresholds
    EvidenceFirstKernel, # Requires evidence field
    DualChannelKernel,   # Requires constraints dict
    
    # Tooling
    ToolRegistry,        # Tool registration + dispatch
    
    # Evidence
    replay_and_verify,   # External verification
    verify_evidence_bundle,
)
```

If a module is not reachable via `kernels.api`, it is **not** a supported API surface.

---

## Kernel Variants

Variants tune posture while preserving invariants:

| Variant | Posture | Key Requirement |
|---------|---------|-----------------|
| **StrictKernel** | Maximal enforcement | Strict ambiguity handling |
| **PermissiveKernel** | Relaxed thresholds | Intent-only allowed |
| **EvidenceFirstKernel** | Evidence-required | `evidence` field mandatory |
| **DualChannelKernel** | Structured constraints | `constraints` dict required |

---

## Quickstart

```bash
git clone https://github.com/ayais12210-hub/kernels.git
cd kernels
python -m pip install -e .
python -m unittest discover -s tests -v
bash scripts/smoke.sh
python examples/01_minimal_request.py
python -m kernels --help
```

---

## Specs + Docs

**Specifications** (normative):

| Document | Content |
|----------|---------|
| [spec/SPEC.md](spec/SPEC.md) | Normative requirements |
| [spec/STATES.md](spec/STATES.md) | State machine + transitions |
| [spec/JURISDICTION.md](spec/JURISDICTION.md) | Policy rules |
| [spec/AUDIT.md](spec/AUDIT.md) | Ledger + hashing + evidence bundle |
| [spec/ERROR_MODEL.md](spec/ERROR_MODEL.md) | Error taxonomy |
| [spec/VARIANTS.md](spec/VARIANTS.md) | Posture variants |

**Architecture + Threat Model**:

| Document | Content |
|----------|---------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component boundaries and data flows |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Adversary model + mitigations |
| [docs/pipelines/HPC_CICD_ARCHITECTURE.md](docs/pipelines/HPC_CICD_ARCHITECTURE.md) | Production-grade CI/CD architecture for kernel projects |
| [docs/FAQ.md](docs/FAQ.md) | Usage clarifications |

---

## What This Refuses To Be

| Not This | Because |
|----------|---------|
| LLM wrapper | Doesn't call models |
| Prompt framework | Doesn't "improve" prompts |
| Agent framework | Doesn't define behaviour |
| "Alignment" | Doesn't solve values |
| RBAC | Jurisdiction is execution-boundary enforcement |
| Dashboard | Outputs evidence; visualisation is out of scope |

It does one job: **deterministic arbitration with immutable audit**.

---

## Versioning Policy

SemVer with strict interpretation:

| Version | Meaning |
|---------|---------|
| `0.x.y` | Development; invariants stable; API may change |
| `1.0.0` | Invariants + API surface frozen |

**Breaking change** = any change to invariants, transitions, audit schema, or public types.

---

## Contributing / Security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE)
