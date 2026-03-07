# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Added

- Expanded CI workflow to run a Python 3.9-3.12 matrix with linting, format checks, type checking, security scanning, coverage-enforced tests, smoke verification, and package build validation.
- Added dedicated smoke workflow for pull requests and manual dispatch execution.
- Added thread-safe nonce registry reference implementation with TTL cleanup support and observability metrics via `stats()`.
- Added SQLite audit storage reference implementation with append/list operations and service diagnostics through `health()`.
- Added coverage tests for the reference implementations.
- Added developer automation improvements to the Makefile for formatting checks, smoke tests, dependency scanning, and build verification.

### Changed

- Extended the security workflow with dependency review, CodeQL scheduling, vulnerability scans (`safety` and `pip-audit`), and secret scanning using gitleaks.
- Extended smoke script coverage to execute reference implementation runtime checks.
- Updated release workflow to verify distribution metadata with `twine check` before PyPI publishing.

## [0.1.0] - 2026-01-01

### Added

- Initial kernel implementation with deterministic state machine
- Core types: KernelState, KernelRequest, KernelReceipt, Decision, ReceiptStatus
- Append-only audit ledger with hash-chained entries
- Jurisdiction policy engine with composable rules
- Tool registry with built-in `echo` and `add` tools
- Four kernel variants: strict, permissive, evidence-first, dual-channel
- Replay verification for audit ledger
- CLI entrypoint with help and version commands
- Formal specification pack under `/spec`
- Five working examples demonstrating core functionality
- Complete test suite

### Fixed

- N/A (initial release)

### Changed

- N/A (initial release)

### Removed

- N/A (initial release)

### Security

- Fail-closed semantics enforced by default
- Hash chain integrity verification on replay
- Jurisdiction checks mandatory before execution
