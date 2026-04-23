#!/usr/bin/env python3
"""Attach benchmark metrics to a Codex run directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def derive_delta(metrics: dict[str, Any]) -> float:
    baseline = float(metrics.get("baseline_latency", 0.0))
    candidate = float(metrics.get("candidate_latency", 0.0))
    if baseline <= 0:
        return 0.0
    return ((candidate - baseline) / baseline) * 100.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("metrics_file", type=Path)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()

    metrics = read_json(args.metrics_file)
    if "delta" not in metrics:
        metrics["delta"] = round(derive_delta(metrics), 4)

    args.run_dir.mkdir(parents=True, exist_ok=True)
    out_file = args.run_dir / "metrics.json"
    out_file.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"metrics_written={out_file}")


if __name__ == "__main__":
    main()
