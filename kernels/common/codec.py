"""Codec utilities for deterministic serialization.

All serialization is deterministic with sorted keys to ensure consistent
hashing and reproducible behavior across platforms.
"""

import json
from typing import Any


def serialize_deterministic(data: Any) -> str:
    """Serialize data to JSON with deterministic ordering.
    
    Keys are sorted to ensure consistent output. No whitespace is added
    to minimize size and ensure byte-for-byte reproducibility.
    
    Args:
        data: Data to serialize. Must be JSON-serializable.
        
    Returns:
        JSON string with sorted keys and no extra whitespace.
        
    Raises:
        TypeError: If data is not JSON-serializable.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def deserialize(data: str) -> Any:
    """Deserialize JSON string to Python object.
    
    Args:
        data: JSON string to deserialize.
        
    Returns:
        Deserialized Python object.
        
    Raises:
        json.JSONDecodeError: If data is not valid JSON.
    """
    return json.loads(data)


def serialize_for_audit(
    request_id: str,
    actor: str,
    intent: str,
    decision: str,
    state_from: str,
    state_to: str,
    ts_ms: int,
    tool_name: str | None = None,
    params_hash: str | None = None,
    evidence_hash: str | None = None,
    error: str | None = None,
    permit_digest: str | None = None,
    permit_verification: str | None = None,
    permit_denial_reasons: tuple[str, ...] | None = None,
    proposal_hash: str | None = None,
    permit_nonce: str | None = None,
    permit_issuer: str | None = None,
    permit_subject: str | None = None,
    permit_max_executions: int | None = None,
) -> str:
    """Serialize audit entry data for hashing.

    Creates a deterministic string representation of audit entry fields
    for use in hash chain computation.

    Args:
        request_id: Unique request identifier.
        actor: Actor who submitted the request.
        intent: Intent of the request.
        decision: Decision made by the kernel.
        state_from: State before transition.
        state_to: State after transition.
        ts_ms: Timestamp in milliseconds.
        tool_name: Name of tool executed, if any.
        params_hash: Hash of parameters, if any.
        evidence_hash: Hash of evidence, if any.
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
        Deterministic string representation for hashing.
    """
    entry_dict = {
        "request_id": request_id,
        "actor": actor,
        "intent": intent,
        "decision": decision,
        "state_from": state_from,
        "state_to": state_to,
        "ts_ms": ts_ms,
        "tool_name": tool_name,
        "params_hash": params_hash,
        "evidence_hash": evidence_hash,
        "error": error,
        "permit_digest": permit_digest,
        "permit_verification": permit_verification,
        "permit_denial_reasons": list(permit_denial_reasons) if permit_denial_reasons else None,
        "proposal_hash": proposal_hash,
        "permit_nonce": permit_nonce,
        "permit_issuer": permit_issuer,
        "permit_subject": permit_subject,
        "permit_max_executions": permit_max_executions,
    }
    return serialize_deterministic(entry_dict)


def audit_entry_to_dict(entry: Any) -> dict[str, Any]:
    """Convert an AuditEntry to a dictionary.

    Args:
        entry: AuditEntry instance.

    Returns:
        Dictionary representation of the entry.
    """
    result = {
        "ledger_seq": entry.ledger_seq if hasattr(entry, "ledger_seq") else 0,
        "prev_hash": entry.prev_hash,
        "entry_hash": entry.entry_hash,
        "ts_ms": entry.ts_ms,
        "request_id": entry.request_id,
        "actor": entry.actor,
        "intent": entry.intent,
        "decision": entry.decision.value if hasattr(entry.decision, "value") else entry.decision,
        "state_from": entry.state_from.value if hasattr(entry.state_from, "value") else entry.state_from,
        "state_to": entry.state_to.value if hasattr(entry.state_to, "value") else entry.state_to,
        "tool_name": entry.tool_name,
        "params_hash": entry.params_hash,
        "evidence_hash": entry.evidence_hash,
        "error": entry.error,
    }

    # Add permit fields if present (v0.2.0+)
    if hasattr(entry, "permit_digest"):
        result["permit_digest"] = entry.permit_digest
    if hasattr(entry, "permit_verification"):
        result["permit_verification"] = entry.permit_verification
    if hasattr(entry, "permit_denial_reasons"):
        result["permit_denial_reasons"] = list(entry.permit_denial_reasons) if entry.permit_denial_reasons else None
    if hasattr(entry, "proposal_hash"):
        result["proposal_hash"] = entry.proposal_hash
    if hasattr(entry, "permit_nonce"):
        result["permit_nonce"] = entry.permit_nonce
    if hasattr(entry, "permit_issuer"):
        result["permit_issuer"] = entry.permit_issuer
    if hasattr(entry, "permit_subject"):
        result["permit_subject"] = entry.permit_subject
    if hasattr(entry, "permit_max_executions"):
        result["permit_max_executions"] = entry.permit_max_executions

    return result
