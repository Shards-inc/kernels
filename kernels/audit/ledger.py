"""Append-only audit ledger implementation.

The audit ledger maintains a hash-chained sequence of entries. Each entry
includes the hash of the previous entry, ensuring tamper detection.
"""

from typing import Any, Optional

from kernels.common.types import (
    AuditEntry,
    Decision,
    EvidenceBundle,
    KernelState,
)
from kernels.common.errors import AuditError
from kernels.common.hashing import (
    compute_chain_hash,
    compute_hash_dict,
    genesis_hash,
)
from kernels.common.codec import serialize_for_audit, audit_entry_to_dict


class AuditLedger:
    """Append-only audit ledger with hash-chained entries.
    
    The ledger enforces append-only semantics. Entries cannot be modified
    or removed once added. The hash chain allows verification of integrity.
    """

    def __init__(self, kernel_id: str, variant: str) -> None:
        """Initialize an empty audit ledger.
        
        Args:
            kernel_id: Identifier of the kernel this ledger belongs to.
            variant: Variant name of the kernel.
        """
        self._kernel_id = kernel_id
        self._variant = variant
        self._entries: list[AuditEntry] = []
        self._last_hash = genesis_hash()
        self._next_seq = 0  # Monotonic sequence counter for deterministic ordering

    @property
    def kernel_id(self) -> str:
        """Return the kernel ID."""
        return self._kernel_id

    @property
    def variant(self) -> str:
        """Return the kernel variant."""
        return self._variant

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        """Return all entries as an immutable tuple."""
        return tuple(self._entries)

    @property
    def root_hash(self) -> str:
        """Return the current root hash (hash of last entry)."""
        return self._last_hash

    @property
    def length(self) -> int:
        """Return the number of entries in the ledger."""
        return len(self._entries)

    def append(
        self,
        request_id: str,
        actor: str,
        intent: str,
        decision: Decision,
        state_from: KernelState,
        state_to: KernelState,
        ts_ms: int,
        tool_name: Optional[str] = None,
        params: Optional[dict[str, Any]] = None,
        evidence: Optional[str] = None,
        error: Optional[str] = None,
        permit_digest: Optional[str] = None,
        permit_verification: Optional[str] = None,
        permit_denial_reasons: Optional[tuple[str, ...]] = None,
        proposal_hash: Optional[str] = None,
        permit_nonce: Optional[str] = None,
        permit_issuer: Optional[str] = None,
        permit_subject: Optional[str] = None,
        permit_max_executions: Optional[int] = None,
    ) -> AuditEntry:
        """Append a new entry to the ledger.

        Args:
            request_id: Unique request identifier.
            actor: Actor who submitted the request.
            intent: Intent of the request.
            decision: Decision made by the kernel.
            state_from: State before transition.
            state_to: State after transition.
            ts_ms: Timestamp in milliseconds.
            tool_name: Name of tool executed, if any.
            params: Parameters passed to tool, if any.
            evidence: Evidence string, if any.
            error: Error message, if any.
            permit_digest: Permit ID if permit was used (v0.2.0+).
            permit_verification: "ALLOW" | "DENY" if permit was verified (v0.2.0+).
            permit_denial_reasons: Reason codes if permit denied (v0.2.0+).
            proposal_hash: Hash of proposal that initiated this request (v0.2.0+).
            permit_nonce: Nonce from permit for ledger-backed replay protection (v0.2.0+).
            permit_issuer: Issuer identity for nonce reconstruction (v0.2.0+).
            permit_subject: Subject identity for nonce reconstruction (v0.2.0+).
            permit_max_executions: Max executions for nonce reconstruction (v0.2.0+).

        Returns:
            The newly created audit entry.

        Raises:
            AuditError: If entry creation fails.
        """
        try:
            # Compute hashes for params and evidence
            params_hash = compute_hash_dict(params) if params else None
            evidence_hash = compute_hash_dict({"evidence": evidence}) if evidence else None

            # Serialize entry data for hashing
            entry_data = serialize_for_audit(
                request_id=request_id,
                actor=actor,
                intent=intent,
                decision=decision.value,
                state_from=state_from.value,
                state_to=state_to.value,
                ts_ms=ts_ms,
                tool_name=tool_name,
                params_hash=params_hash,
                evidence_hash=evidence_hash,
                error=error,
                permit_digest=permit_digest,
                permit_verification=permit_verification,
                permit_denial_reasons=permit_denial_reasons,
                proposal_hash=proposal_hash,
                permit_nonce=permit_nonce,
                permit_issuer=permit_issuer,
                permit_subject=permit_subject,
                permit_max_executions=permit_max_executions,
            )

            # Compute entry hash using chain
            entry_hash = compute_chain_hash(self._last_hash, entry_data)

            # Assign sequence number
            ledger_seq = self._next_seq

            # Create entry
            entry = AuditEntry(
                ledger_seq=ledger_seq,
                prev_hash=self._last_hash,
                entry_hash=entry_hash,
                ts_ms=ts_ms,
                request_id=request_id,
                actor=actor,
                intent=intent,
                decision=decision,
                state_from=state_from,
                state_to=state_to,
                tool_name=tool_name,
                params_hash=params_hash,
                evidence_hash=evidence_hash,
                error=error,
                permit_digest=permit_digest,
                permit_verification=permit_verification,
                permit_denial_reasons=permit_denial_reasons or tuple(),
                proposal_hash=proposal_hash,
                permit_nonce=permit_nonce,
                permit_issuer=permit_issuer,
                permit_subject=permit_subject,
                permit_max_executions=permit_max_executions,
            )

            # Append and update chain
            self._entries.append(entry)
            self._last_hash = entry_hash
            self._next_seq += 1  # Increment sequence counter

            return entry

        except Exception as e:
            raise AuditError(f"Failed to append audit entry: {e}")

    def export(self, ts_ms: int) -> EvidenceBundle:
        """Export the ledger as an evidence bundle.
        
        Args:
            ts_ms: Timestamp of export in milliseconds.
            
        Returns:
            EvidenceBundle containing all entries and verification data.
        """
        return EvidenceBundle(
            ledger_entries=tuple(self._entries),
            root_hash=self._last_hash,
            exported_at_ms=ts_ms,
            kernel_id=self._kernel_id,
            variant=self._variant,
        )

    def to_list(self) -> list[dict[str, Any]]:
        """Convert ledger to list of dictionaries for serialization.
        
        Returns:
            List of entry dictionaries.
        """
        return [audit_entry_to_dict(entry) for entry in self._entries]
