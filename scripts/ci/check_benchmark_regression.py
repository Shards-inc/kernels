#!/usr/bin/env python3
"""Fail CI when benchmark median latency regresses above a threshold.

Usage:
  python scripts/ci/check_benchmark_regression.py <current-json> <max-regression-ratio>

The baseline file path is `.ci/benchmarks/baseline.json`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BASELINE_PATH = Path(".ci/benchmarks/baseline.json")


def _load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _median_map(payload: dict) -> dict[str, float]:
    benchmarks = payload.get("benchmarks", [])
    result: dict[str, float] = {}
    for benchmark in benchmarks:
        name = benchmark.get("name")
        median = benchmark.get("stats", {}).get("median")
        if name is None or median is None:
            continue
        result[str(name)] = float(median)
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: check_benchmark_regression.py <current-json> <max-regression-ratio>"
        )
        return 2

    current_path = Path(sys.argv[1])
    max_regression = float(sys.argv[2])

    if not current_path.exists():
        print(f"Current benchmark report not found: {current_path}")
        return 2

    if not BASELINE_PATH.exists():
        print(
            f"Baseline benchmark file not found at {BASELINE_PATH}; skipping regression gate."
        )
        return 0

    current = _median_map(_load(current_path))
    baseline = _median_map(_load(BASELINE_PATH))

    failures: list[str] = []
    for name, baseline_median in baseline.items():
        current_median = current.get(name)
        if current_median is None:
            failures.append(f"{name}: missing from current benchmark run")
            continue

        if baseline_median <= 0:
            continue

        regression = (current_median - baseline_median) / baseline_median
        if regression > max_regression:
            failures.append(
                f"{name}: baseline={baseline_median:.6f}s current={current_median:.6f}s "
                f"regression={regression * 100:.2f}% > {max_regression * 100:.2f}%"
            )

    if failures:
        print("Performance regression gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Benchmark regression gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
