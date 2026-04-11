#!/usr/bin/env python3
"""Example 04: External Audit Replay

Demonstrates exporting an audit ledger and verifying it externally through
replay.
"""

import json

from kernels.common.types import (
    KernelConfig,
    KernelRequest,
    ToolCall,
    VirtualClock,
)
from kernels.variants.strict_kernel import StrictKernel
from kernels.audit.replay import verify_evidence_bundle
from kernels.common.codec import audit_entry_to_dict


def main() -> None:
    """Run external audit replay example."""
    print("External Audit Replay Verification")
    print("=" * 50)

    # Phase 1: Generate audit trail
    print("\n[Phase 1: Generate Audit Trail]")

    kernel = StrictKernel()
    config = KernelConfig(
        kernel_id="audit-example-001",
        variant="strict",
        clock=VirtualClock(1000),
    )
    kernel.boot(config)

    # Submit several requests
    requests = [
        KernelRequest(
            request_id="req-001",
            ts_ms=1000,
            actor="alice",
            intent="First operation",
            tool_call=ToolCall(name="echo", params={"text": "first"}),
        ),
        KernelRequest(
            request_id="req-002",
            ts_ms=2000,
            actor="bob",
            intent="Second operation",
            tool_call=ToolCall(name="add", params={"a": 10, "b": 20}),
        ),
        KernelRequest(
            request_id="req-003",
            ts_ms=3000,
            actor="alice",
            intent="Third operation",
            tool_call=ToolCall(name="echo", params={"text": "third"}),
        ),
    ]

    for request in requests:
        receipt = kernel.submit(request)
        print(f"  {request.request_id}: {receipt.decision.value}")

    # Phase 2: Export evidence
    print("\n[Phase 2: Export Evidence Bundle]")

    evidence = kernel.export_evidence()
    print(f"  Kernel ID: {evidence.kernel_id}")
    print(f"  Entries: {len(evidence.ledger_entries)}")
    print(f"  Root hash: {evidence.root_hash[:32]}...")

    # Convert to serializable format (simulating external storage)
    evidence_dict = {
        "kernel_id": evidence.kernel_id,
        "variant": evidence.variant,
        "exported_at_ms": evidence.exported_at_ms,
        "root_hash": evidence.root_hash,
        "ledger_entries": [
            audit_entry_to_dict(entry) for entry in evidence.ledger_entries
        ],
    }

    # Serialize to JSON (simulating storage/transmission)
    evidence_json = json.dumps(evidence_dict, indent=2)
    print(f"\n  Serialized size: {len(evidence_json)} bytes")

    # Phase 3: External verification
    print("\n[Phase 3: External Verification]")

    # Parse from JSON (simulating external verifier)
    loaded_evidence = json.loads(evidence_json)

    # Verify using replay
    result = verify_evidence_bundle(loaded_evidence)

    print(f"  Valid: {result.is_valid}")
    print(f"  Entries verified: {result.entries_verified}")
    print(f"  Computed root: {result.computed_root_hash[:32]}...")

    if result.errors:
        print("  Errors:")
        for error in result.errors:
            print(f"    - {error}")
    else:
        print("  No errors detected.")

    # Phase 4: Demonstrate tamper detection
    print("\n[Phase 4: Tamper Detection]")

    # Tamper with an entry
    tampered_evidence = json.loads(evidence_json)
    tampered_evidence["ledger_entries"][1]["intent"] = "TAMPERED INTENT"

    tampered_result = verify_evidence_bundle(tampered_evidence)

    print(f"  Tampered ledger valid: {tampered_result.is_valid}")
    if tampered_result.errors:
        print("  Detected issues:")
        for error in tampered_result.errors:
            print(f"    - {error[:60]}...")


if __name__ == "__main__":
    main()
