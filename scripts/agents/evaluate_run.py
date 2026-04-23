#!/usr/bin/env python3
"""Evaluate a Codex run and persist leaderboard + memory artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def score_run(metrics: dict[str, Any], request: dict[str, Any], outcomes: dict[str, Any]) -> float:
    latency_delta = float(metrics.get("delta", 0.0))
    memory_increase = float(metrics.get("memory_increase", 0.0))
    test_failures = int(outcomes.get("test_failures", 0))
    abi_break = 1 if request.get("failure_type") == "abi_break" else 0

    score = 100.0
    score -= latency_delta * 2.0
    score -= memory_increase * 1.5
    score -= test_failures * 5.0
    score -= abi_break * 10.0
    return round(score, 4)


def update_leaderboard(meta_dir: Path, record: dict[str, Any]) -> None:
    board_file = meta_dir / "leaderboard.json"
    board = read_json(board_file)
    entries = board.get("entries", [])
    entries.append(record)
    entries = sorted(entries, key=lambda item: float(item["score"]), reverse=True)[:100]
    write_json(board_file, {"entries": entries})


def increment_pattern(store: dict[str, Any], key: str, value: str) -> dict[str, Any]:
    bucket = store.get(key, {})
    bucket[value] = int(bucket.get(value, 0)) + 1
    store[key] = bucket
    return store


def update_memory(memory_dir: Path, request: dict[str, Any], score: float) -> None:
    failure_file = memory_dir / "failure_patterns.json"
    success_file = memory_dir / "successful_strategies.json"

    failure_store = read_json(failure_file)
    success_store = read_json(success_file)

    failure_type = str(request.get("failure_type", "unknown"))
    strategy = str(request.get("repair_strategy", "unknown"))

    increment_pattern(failure_store, "failure_type", failure_type)
    if score >= 90.0:
        increment_pattern(success_store, "repair_strategy", strategy)

    write_json(failure_file, failure_store)
    write_json(success_file, success_store)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--meta-dir", type=Path, default=Path(".codex/meta"))
    parser.add_argument("--memory-dir", type=Path, default=Path(".codex/memory"))
    parser.add_argument("--test-failures", type=int, default=0)
    args = parser.parse_args()

    request = read_json(args.run_dir / "request.json")
    metrics = read_json(args.run_dir / "metrics.json")
    outcomes = {"test_failures": args.test_failures}
    score = score_run(metrics, request, outcomes)

    record = {
        "run_dir": str(args.run_dir),
        "score": score,
        "failure_type": request.get("failure_type", "unknown"),
        "repair_strategy": request.get("repair_strategy", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    update_leaderboard(args.meta_dir, record)
    update_memory(args.memory_dir, request, score)
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
