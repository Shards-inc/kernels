#!/usr/bin/env python3
"""Run the full Codex scaffold loop for a single issue payload."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def run_command(args: list[str]) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout


def parse_keyed_output(output: str, key: str) -> str:
    for line in output.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", maxsplit=1)[1].strip()
    raise RuntimeError(f"Expected '{key}=' in command output")


def ensure_metrics(run_dir: Path, metrics_file: Path | None) -> None:
    if metrics_file is None:
        default_metrics = {
            "baseline_latency": 1.0,
            "candidate_latency": 1.0,
            "memory_increase": 0.0,
            "delta": 0.0,
        }
        metrics_file = run_dir / "default-metrics.json"
        metrics_file.write_text(json.dumps(default_metrics, indent=2), encoding="utf-8")

    run_command(
        [
            sys.executable,
            "scripts/agents/append_metrics.py",
            str(metrics_file),
            str(run_dir),
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("issue_payload", type=Path)
    parser.add_argument("--metrics", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=Path(".codex/runs"))
    parser.add_argument("--memory-dir", type=Path, default=Path(".codex/memory"))
    parser.add_argument("--meta-dir", type=Path, default=Path(".codex/meta"))
    args = parser.parse_args()

    generate_output = run_command(
        [
            sys.executable,
            "scripts/agents/codex_generate_patch.py",
            str(args.issue_payload),
            "--out-dir",
            str(args.out_dir),
        ]
    )
    run_dir = Path(parse_keyed_output(generate_output, "codex_run_dir"))

    ensure_metrics(run_dir, args.metrics)

    run_command(
        [
            sys.executable,
            "scripts/agents/build_codex_prompt.py",
            str(run_dir / "request.json"),
            "--run-dir",
            str(run_dir),
            "--memory-dir",
            str(args.memory_dir),
            "--out",
            str(run_dir / "prompt.json"),
        ]
    )

    evaluation_output = run_command(
        [
            sys.executable,
            "scripts/agents/evaluate_run.py",
            str(run_dir),
            "--meta-dir",
            str(args.meta_dir),
            "--memory-dir",
            str(args.memory_dir),
        ]
    )

    result: dict[str, Any] = {
        "run_dir": str(run_dir),
        "request": str(run_dir / "request.json"),
        "metrics": str(run_dir / "metrics.json"),
        "prompt": str(run_dir / "prompt.json"),
        "evaluation": json.loads(evaluation_output),
        "leaderboard": str(args.meta_dir / "leaderboard.json"),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
