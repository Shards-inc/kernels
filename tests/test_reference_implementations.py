"""Tests for standalone production-oriented reference implementations."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from implementations.permits_threadsafe import ThreadSafeNonceRegistry
from implementations.storage import SQLiteAuditStorage


def _sample_entry(seq: int) -> dict[str, object]:
    return {
        "ledger_seq": seq,
        "entry_hash": f"hash-{seq}",
        "prev_hash": f"hash-{seq - 1}" if seq > 1 else "genesis",
        "ts_ms": 1710000000000 + seq,
        "request_id": f"req-{seq}",
        "actor": "tester",
        "intent": "validate",
        "decision": "allow",
        "state_from": "requested",
        "state_to": "approved",
    }


def test_threadsafe_nonce_registry_enforces_max_executions() -> None:
    registry = ThreadSafeNonceRegistry()

    assert registry.check_and_record(
        "nonce-1", "issuer", "subject", "permit-1", 2, 1000
    )
    assert registry.check_and_record(
        "nonce-1", "issuer", "subject", "permit-1", 2, 1001
    )
    assert not registry.check_and_record(
        "nonce-1", "issuer", "subject", "permit-1", 2, 1002
    )

    stats = registry.stats()
    assert stats["size"] == 1
    assert stats["ttl_ms"] is None


def test_threadsafe_nonce_registry_parallel_access() -> None:
    registry = ThreadSafeNonceRegistry()

    def _op(i: int) -> bool:
        return registry.check_and_record(
            nonce=f"nonce-{i % 5}",
            issuer="issuer",
            subject="subject",
            permit_id=f"permit-{i}",
            max_executions=100,
            current_time_ms=2000 + i,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(_op, range(40)))

    assert all(outcomes)
    assert registry.size() == 5


def test_threadsafe_nonce_registry_cleanup_ttl() -> None:
    registry = ThreadSafeNonceRegistry(ttl_ms=50)

    registry.check_and_record("nonce-1", "issuer", "subject", "permit-1", 1, 1000)
    registry.check_and_record("nonce-2", "issuer", "subject", "permit-2", 1, 1020)
    removed = registry.cleanup(current_time_ms=1060)

    assert removed == 1
    assert registry.size() == 1
    assert registry.stats()["cleaned_records"] >= 1


def test_sqlite_audit_storage_append_list_and_health(tmp_path) -> None:
    storage = SQLiteAuditStorage(str(tmp_path / "audit.db"))

    storage.append("kernel-a", _sample_entry(1))
    storage.append("kernel-a", _sample_entry(2))
    storage.append("kernel-b", _sample_entry(1))

    kernel_a_entries = storage.list_entries("kernel-a")
    assert [entry["ledger_seq"] for entry in kernel_a_entries] == [1, 2]

    health = storage.health()
    assert health["ok"] is True
    assert health["entries"] == 3
