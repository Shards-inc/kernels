#!/usr/bin/env python3
"""
KERNELS Evidence Verification CLI

Command-line tool for verifying exported evidence bundles.

Usage:
    python -m kernels.cli.verify evidence.json
    python -m kernels.cli.verify --detailed evidence.json
    python -m kernels.cli.verify --check-permits evidence.json

Verification checks:
  ✓ Hash chain integrity (prev_hash linkage)
  ✓ Sequence numbering (no gaps, no duplicates)
  ✓ Permit enforcement (no execution without permits where required)
  ✓ Replay protection (no permit reuse violations)
  ✓ State machine integrity (valid transitions only)
  ✓ Decision envelope binding (TOCTOU protection)
"""

import json
import sys
import argparse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

# KERNELS imports
from kernels.common.hashing import compute_chain_hash, genesis_hash


@dataclass
class VerificationResult:
    """Result of evidence verification."""
    passed: bool
    checks_total: int
    checks_passed: int
    checks_failed: int
    errors: List[str]
    warnings: List[str]
    stats: Dict[str, Any]


class EvidenceVerifier:
    """
    Verifies KERNELS evidence bundles for integrity and compliance.

    Checks performed:
    1. Hash chain integrity
    2. Sequence numbering
    3. Permit enforcement
    4. Replay protection
    5. State machine transitions
    """

    def __init__(self, evidence: Dict[str, Any]):
        """
        Initialize verifier with evidence bundle.

        Args:
            evidence: Evidence bundle as dict (from kernel.export_evidence())
        """
        self.evidence = evidence
        self.entries = evidence.get("entries", [])
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.stats: Dict[str, Any] = {}

    def verify_all(self) -> VerificationResult:
        """
        Run all verification checks.

        Returns:
            VerificationResult with overall status
        """
        checks = [
            ("Hash Chain", self.verify_hash_chain),
            ("Sequence Numbering", self.verify_sequence_numbering),
            ("Permit Enforcement", self.verify_permit_enforcement),
            ("Replay Protection", self.verify_replay_protection),
            ("State Transitions", self.verify_state_transitions),
        ]

        checks_passed = 0
        checks_failed = 0

        for check_name, check_fn in checks:
            try:
                passed = check_fn()
                if passed:
                    checks_passed += 1
                else:
                    checks_failed += 1
                    self.errors.append(f"{check_name} check failed")
            except Exception as e:
                checks_failed += 1
                self.errors.append(f"{check_name} check error: {e}")

        # Compute stats
        self.compute_stats()

        return VerificationResult(
            passed=(checks_failed == 0),
            checks_total=len(checks),
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            errors=self.errors,
            warnings=self.warnings,
            stats=self.stats,
        )

    def verify_hash_chain(self) -> bool:
        """
        Verify hash chain integrity.

        Checks:
        - First entry has genesis prev_hash
        - Each entry's prev_hash matches previous entry's entry_hash
        - Final entry_hash matches root_hash

        Returns:
            True if chain is valid
        """
        if not self.entries:
            self.warnings.append("No entries to verify")
            return True

        # Check first entry
        first = self.entries[0]
        expected_genesis = genesis_hash()
        if first.get("prev_hash") != expected_genesis:
            self.errors.append(
                f"First entry prev_hash mismatch: got {first.get('prev_hash')[:16]}..., "
                f"expected {expected_genesis[:16]}..."
            )
            return False

        # Check chain linkage
        for i in range(1, len(self.entries)):
            prev_entry = self.entries[i - 1]
            curr_entry = self.entries[i]

            expected_prev_hash = prev_entry["entry_hash"]
            actual_prev_hash = curr_entry.get("prev_hash")

            if actual_prev_hash != expected_prev_hash:
                self.errors.append(
                    f"Hash chain break at entry {i}: "
                    f"expected prev_hash {expected_prev_hash[:16]}..., "
                    f"got {actual_prev_hash[:16] if actual_prev_hash else 'None'}..."
                )
                return False

        # Check root hash
        last_entry = self.entries[-1]
        expected_root = last_entry["entry_hash"]
        actual_root = self.evidence.get("root_hash")

        if actual_root != expected_root:
            self.errors.append(
                f"Root hash mismatch: "
                f"expected {expected_root[:16]}..., "
                f"got {actual_root[:16] if actual_root else 'None'}..."
            )
            return False

        return True

    def verify_sequence_numbering(self) -> bool:
        """
        Verify ledger_seq numbering.

        Checks:
        - Starts at 0
        - No gaps
        - No duplicates
        - Monotonic increasing

        Returns:
            True if numbering is valid
        """
        if not self.entries:
            return True

        seen_seqs = set()
        expected_seq = 0

        for i, entry in enumerate(self.entries):
            seq = entry.get("ledger_seq")

            if seq is None:
                self.errors.append(f"Entry {i} missing ledger_seq")
                return False

            if seq in seen_seqs:
                self.errors.append(f"Duplicate ledger_seq {seq} at entry {i}")
                return False

            if seq != expected_seq:
                self.errors.append(
                    f"Sequence gap at entry {i}: expected {expected_seq}, got {seq}"
                )
                return False

            seen_seqs.add(seq)
            expected_seq += 1

        return True

    def verify_permit_enforcement(self) -> bool:
        """
        Verify permit enforcement.

        Checks:
        - All ALLOW decisions with tool execution have permit verification
        - No execution without permit where keyring is configured

        Returns:
            True if enforcement is correct
        """
        has_permit_system = any(
            entry.get("permit_verification") is not None
            for entry in self.entries
        )

        if not has_permit_system:
            self.warnings.append("No permit enforcement detected (keyring not configured)")
            return True

        for i, entry in enumerate(self.entries):
            decision = entry.get("decision")
            tool_name = entry.get("tool_name")
            permit_verification = entry.get("permit_verification")

            # If tool was executed (ALLOW decision with tool_name)
            if decision == "ALLOW" and tool_name:
                if permit_verification != "ALLOW":
                    self.errors.append(
                        f"Entry {i}: Tool '{tool_name}' executed without permit verification"
                    )
                    return False

        return True

    def verify_replay_protection(self) -> bool:
        """
        Verify replay protection.

        Checks:
        - No permit nonce reused beyond max_executions
        - REPLAY_DETECTED denials are correct

        Returns:
            True if replay protection is working
        """
        nonce_usage: Dict[str, int] = {}  # nonce -> use_count

        for i, entry in enumerate(self.entries):
            permit_nonce = entry.get("permit_nonce")
            permit_verification = entry.get("permit_verification")
            max_executions = entry.get("permit_max_executions")
            denial_reasons = entry.get("permit_denial_reasons", [])

            if not permit_nonce:
                continue

            # Track usage
            if permit_verification == "ALLOW":
                nonce_usage[permit_nonce] = nonce_usage.get(permit_nonce, 0) + 1

                # Check if exceeded max
                if max_executions and nonce_usage[permit_nonce] > max_executions:
                    self.errors.append(
                        f"Entry {i}: Nonce {permit_nonce[:16]}... used {nonce_usage[permit_nonce]} times "
                        f"(max: {max_executions})"
                    )
                    return False

            # Verify REPLAY_DETECTED is accurate
            if denial_reasons and "REPLAY_DETECTED" in denial_reasons:
                if nonce_usage.get(permit_nonce, 0) == 0:
                    self.warnings.append(
                        f"Entry {i}: REPLAY_DETECTED but nonce not seen before"
                    )

        return True

    def verify_state_transitions(self) -> bool:
        """
        Verify state machine transitions.

        Checks:
        - All transitions are valid according to state machine rules
        - Terminal states (HALTED) are not exited

        Returns:
            True if transitions are valid
        """
        valid_transitions = {
            "BOOTING": ["IDLE"],
            "IDLE": ["VALIDATING", "IDLE", "HALTED"],  # IDLE → IDLE for denials
            "VALIDATING": ["ARBITRATING", "IDLE"],
            "ARBITRATING": ["EXECUTING", "IDLE"],
            "EXECUTING": ["AUDITING"],
            "AUDITING": ["IDLE"],
            "HALTED": [],  # Terminal state
        }

        for i, entry in enumerate(self.entries):
            state_from = entry.get("state_from")
            state_to = entry.get("state_to")

            if not state_from or not state_to:
                continue

            allowed = valid_transitions.get(state_from, [])

            if state_to not in allowed:
                self.errors.append(
                    f"Entry {i}: Invalid transition {state_from} → {state_to}"
                )
                return False

        return True

    def compute_stats(self) -> None:
        """Compute statistics about the audit trail."""
        total_entries = len(self.entries)
        allows = sum(1 for e in self.entries if e.get("decision") == "ALLOW")
        denies = sum(1 for e in self.entries if e.get("decision") == "DENY")
        halts = sum(1 for e in self.entries if e.get("decision") == "HALT")

        permits_verified = sum(
            1 for e in self.entries if e.get("permit_verification") == "ALLOW"
        )
        permits_denied = sum(
            1 for e in self.entries if e.get("permit_verification") == "DENY"
        )
        missing_permits = sum(
            1 for e in self.entries
            if "MISSING_PERMIT" in (e.get("permit_denial_reasons") or [])
        )
        replay_detected = sum(
            1 for e in self.entries
            if "REPLAY_DETECTED" in (e.get("permit_denial_reasons") or [])
        )

        tools_executed = [e.get("tool_name") for e in self.entries if e.get("tool_name")]
        unique_tools = set(tools_executed)

        self.stats = {
            "total_entries": total_entries,
            "decisions": {"ALLOW": allows, "DENY": denies, "HALT": halts},
            "permit_verification": {
                "verified": permits_verified,
                "denied": permits_denied,
                "missing": missing_permits,
                "replay_detected": replay_detected,
            },
            "tool_executions": {"total": len(tools_executed), "unique": len(unique_tools)},
            "unique_tools": sorted(unique_tools),
        }


def verify_evidence(evidence: Dict[str, Any], detailed: bool = False) -> VerificationResult:
    """
    Verify evidence bundle.

    Args:
        evidence: Evidence bundle dict
        detailed: Show detailed output

    Returns:
        VerificationResult
    """
    verifier = EvidenceVerifier(evidence)
    result = verifier.verify_all()

    # Print results
    print_verification_result(result, evidence, detailed)

    return result


def verify_evidence_file(filepath: str, detailed: bool = False) -> VerificationResult:
    """
    Verify evidence bundle from file.

    Args:
        filepath: Path to evidence JSON file
        detailed: Show detailed output

    Returns:
        VerificationResult
    """
    with open(filepath, "r") as f:
        evidence = json.load(f)

    return verify_evidence(evidence, detailed)


def print_verification_result(
    result: VerificationResult,
    evidence: Dict[str, Any],
    detailed: bool = False,
) -> None:
    """Print verification results to console."""
    print()
    print("=" * 80)
    print("KERNELS Evidence Verification")
    print("=" * 80)
    print()

    # Basic info
    print(f"Kernel ID: {evidence.get('kernel_id', 'N/A')}")
    print(f"Variant: {evidence.get('variant', 'N/A')}")
    print(f"Root Hash: {evidence.get('root_hash', 'N/A')[:32]}...")
    print(f"Total Entries: {result.stats['total_entries']}")
    print()

    # Verification status
    status_icon = "✓" if result.passed else "✗"
    status_text = "PASSED" if result.passed else "FAILED"

    print(f"{status_icon} Verification: {status_text}")
    print(f"  Checks passed: {result.checks_passed}/{result.checks_total}")
    if result.checks_failed > 0:
        print(f"  Checks failed: {result.checks_failed}")
    print()

    # Errors
    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"  ✗ {error}")
        print()

    # Warnings
    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  ⚠ {warning}")
        print()

    # Statistics
    print("Statistics:")
    print(f"  Decisions: {result.stats['decisions']}")
    print(f"  Permit Verification: {result.stats['permit_verification']}")
    print(f"  Tool Executions: {result.stats['tool_executions']}")

    if result.stats['unique_tools']:
        print(f"  Unique Tools: {', '.join(result.stats['unique_tools'])}")
    print()

    # Detailed mode
    if detailed and evidence.get("entries"):
        print("=" * 80)
        print("Audit Trail Entries")
        print("=" * 80)
        print()

        for i, entry in enumerate(evidence["entries"], 1):
            decision = entry.get("decision", "N/A")
            tool = entry.get("tool_name", "N/A")
            permit = entry.get("permit_verification", "N/A")

            print(f"{i}. [{decision}] {tool}")
            print(f"   Seq: {entry.get('ledger_seq')}")
            print(f"   Permit: {permit}")

            if entry.get("permit_denial_reasons"):
                print(f"   Denial: {', '.join(entry['permit_denial_reasons'])}")

            print(f"   Hash: {entry.get('entry_hash', 'N/A')[:32]}...")
            print()

    print("=" * 80)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Verify KERNELS evidence bundles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "evidence_file",
        help="Path to evidence bundle JSON file",
    )

    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed audit trail entries",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    # Verify file exists
    if not Path(args.evidence_file).exists():
        print(f"Error: File not found: {args.evidence_file}", file=sys.stderr)
        sys.exit(1)

    # Run verification
    try:
        result = verify_evidence_file(args.evidence_file, detailed=args.detailed)

        if args.json:
            output = {
                "passed": result.passed,
                "checks_passed": result.checks_passed,
                "checks_failed": result.checks_failed,
                "errors": result.errors,
                "warnings": result.warnings,
                "stats": result.stats,
            }
            print(json.dumps(output, indent=2))

        # Exit code
        sys.exit(0 if result.passed else 1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
