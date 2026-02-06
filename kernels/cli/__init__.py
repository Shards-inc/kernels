"""
KERNELS CLI Tools

Command-line utilities for working with KERNELS evidence and audit trails.
"""

from kernels.cli.verify import verify_evidence, verify_evidence_file

__all__ = [
    "verify_evidence",
    "verify_evidence_file",
]
