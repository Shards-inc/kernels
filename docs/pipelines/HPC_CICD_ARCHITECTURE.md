# HPC CI/CD Architecture for KERNELS

This document defines a production-grade CI/CD design for compute-kernel style
repositories where correctness, determinism, and hardware compatibility are first-
class release gates.

## Pipeline Layers

```text
Commit
  -> Static Analysis
  -> Deterministic Build Matrix
  -> CPU + GPU Test Matrix
  -> Security / Supply Chain
  -> Numerical Validation
  -> Performance Regression Validation
  -> Artifact Packaging + Attestation
  -> Release + Registry Publish
  -> Production Telemetry Hooks
```

## Workflow Set

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR + push | Fast quality checks, unit tests, package build |
| `hpc-matrix.yml` | PR + push + nightly | Expanded matrix with PyTorch/CUDA compatibility checks |
| `gpu-hardware.yml` | nightly + manual + release candidate | Hardware validation on self-hosted GPU runners |
| `security.yml` | PR + push + weekly | SAST, dependency audit, secret scan |
| `benchmark.yml` | PR + nightly | Performance baselines and regression thresholds |
| `release.yml` | tags | Build, verify, and publish release artifacts |
| `docs.yml` | docs changes + release | Build and publish documentation |

## Deterministic Build Strategy

Determinism is enforced by:

1. Pinning lock files and toolchain versions.
2. Building wheels in isolated environments (`python -m build`).
3. Verifying metadata (`twine check`).
4. Capturing SBOM and provenance attestations.

## Build Matrix Recommendation

| Axis | Values |
|------|--------|
| Python | 3.9, 3.10, 3.11, 3.12 |
| PyTorch | Supported minor versions |
| CUDA | 11.8, 12.1, 12.4 |
| GPU arch | sm_80, sm_86, sm_89, sm_90 |
| OS | ubuntu-latest, self-hosted GPU Linux |

## Validation Gates

### 1. Static Quality Gate

- `ruff check .`
- `ruff format --check .`
- `mypy kernels implementations`

### 2. Correctness Gate

- Unit tests with coverage threshold.
- Integration tests for runtime loading and fallback behavior.
- Numerical equivalence checks against reference implementations.

### 3. Hardware Gate

- Run kernel smoke tests on A100 / H100 / RTX-class runners.
- Enforce CPU fallback tests in every PR.

### 4. Security Gate

- CodeQL
- `pip-audit`
- `safety`
- `gitleaks`
- Optional Semgrep policy pack

### 5. Performance Gate

- Pytest benchmark suite with historical comparison.
- Fail CI if median latency regresses beyond threshold (default 5%).

## Release Controls

Release jobs should execute only after all mandatory checks pass:

- Lint / type / tests
- Security scans
- Benchmark regression check
- Docs build

On tag:

1. Build source + wheel distributions.
2. Generate SBOM (`syft`) and vulnerability report (`grype` or `trivy`).
3. Publish to PyPI.
4. Publish container image.
5. Attach benchmark + security artifacts to GitHub release.

## Rollback Policy

If release validation fails for correctness or benchmark thresholds:

- Mark release candidate as failed.
- Prevent publication jobs from running.
- Emit structured summary and incident artifact.

## Scaling Guidance

For large OSS adoption:

- Split fast and slow workflows; protect PR latency.
- Use distributed/self-hosted GPU pools by architecture label.
- Cache Python deps, build layers, and benchmark baselines.
- Nightly deep validation for expensive fuzz + hardware tests.
