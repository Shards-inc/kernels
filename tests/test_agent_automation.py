from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def run_python(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def parse_run_dir(stdout: str) -> Path:
    for line in stdout.splitlines():
        if line.startswith("codex_run_dir="):
            return Path(line.split("=", maxsplit=1)[1])
    raise AssertionError("run directory marker not found")


def test_generate_patch_includes_failure_taxonomy(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    issue_file = tmp_path / "issue.json"
    issue_file.write_text(
        json.dumps(
            {
                "title": "Benchmark latency regression in fused kernel",
                "body": "candidate latency grew by 12%",
            }
        ),
        encoding="utf-8",
    )

    result = run_python(
        "scripts/agents/codex_generate_patch.py",
        str(issue_file),
        "--out-dir",
        str(tmp_path / "runs"),
        cwd=repo_root,
    )
    run_dir = parse_run_dir(result.stdout)
    request = json.loads((run_dir / "request.json").read_text(encoding="utf-8"))

    assert request["failure_type"] == "benchmark_regression"
    assert request["repair_strategy"] == "optimize"


def test_generate_patch_reads_embedded_taxonomy_block(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    issue_file = tmp_path / "issue.json"
    issue_file.write_text(
        json.dumps(
            {
                "title": "Self-heal: CI failed",
                "body": (
                    "Failure summary\n\n```json\n"
                    '{"failure_type":"abi_break","repair_strategy":"restore_compat"}\n'
                    "```"
                ),
            }
        ),
        encoding="utf-8",
    )

    result = run_python(
        "scripts/agents/codex_generate_patch.py",
        str(issue_file),
        "--out-dir",
        str(tmp_path / "runs"),
        cwd=repo_root,
    )
    run_dir = parse_run_dir(result.stdout)
    request = json.loads((run_dir / "request.json").read_text(encoding="utf-8"))

    assert request["failure_type"] == "abi_break"
    assert request["repair_strategy"] == "restore_compat"


def test_append_metrics_and_prompt_include_context(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    request_file = run_dir / "request.json"
    request_file.write_text(
        json.dumps(
            {
                "body": "Improve performance",
                "failure_type": "benchmark_regression",
                "repair_strategy": "optimize",
            }
        ),
        encoding="utf-8",
    )

    metrics_file = tmp_path / "metrics.json"
    metrics_file.write_text(
        json.dumps({"baseline_latency": 1.2, "candidate_latency": 1.35, "memory_increase": 0.1}),
        encoding="utf-8",
    )

    run_python("scripts/agents/append_metrics.py", str(metrics_file), str(run_dir), cwd=repo_root)
    run_python(
        "scripts/agents/build_codex_prompt.py",
        str(request_file),
        "--run-dir",
        str(run_dir),
        "--out",
        str(run_dir / "prompt.json"),
        cwd=repo_root,
    )

    prompt_payload = json.loads((run_dir / "prompt.json").read_text(encoding="utf-8"))
    assert prompt_payload["performance_context"]["delta"] == 12.5
    assert "skills/optimization_strategies.md" in prompt_payload["skills"]


def test_evaluate_run_writes_leaderboard_and_memory(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    run_dir = tmp_path / "runs" / "run-2"
    run_dir.mkdir(parents=True)
    (run_dir / "request.json").write_text(
        json.dumps({"failure_type": "test_failure", "repair_strategy": "adjust_shape"}),
        encoding="utf-8",
    )
    (run_dir / "metrics.json").write_text(
        json.dumps({"delta": 1.0, "memory_increase": 0.0}),
        encoding="utf-8",
    )

    meta_dir = tmp_path / "meta"
    memory_dir = tmp_path / "memory"
    run_python(
        "scripts/agents/evaluate_run.py",
        str(run_dir),
        "--meta-dir",
        str(meta_dir),
        "--memory-dir",
        str(memory_dir),
        cwd=repo_root,
    )

    leaderboard = json.loads((meta_dir / "leaderboard.json").read_text(encoding="utf-8"))
    failures = json.loads((memory_dir / "failure_patterns.json").read_text(encoding="utf-8"))

    assert leaderboard["entries"][0]["run_dir"] == str(run_dir)
    assert failures["failure_type"]["test_failure"] == 1


def test_run_end_to_end_executes_full_loop(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    issue_file = tmp_path / "issue.md"
    issue_file.write_text(
        "Benchmark regression in matmul kernel\ncandidate latency increased",
        encoding="utf-8",
    )
    metrics_file = tmp_path / "metrics.json"
    metrics_file.write_text(
        json.dumps({"baseline_latency": 1.0, "candidate_latency": 1.2, "memory_increase": 0.2}),
        encoding="utf-8",
    )

    result = run_python(
        "scripts/agents/run_end_to_end.py",
        str(issue_file),
        "--metrics",
        str(metrics_file),
        "--out-dir",
        str(tmp_path / "runs"),
        "--meta-dir",
        str(tmp_path / "meta"),
        "--memory-dir",
        str(tmp_path / "memory"),
        cwd=repo_root,
    )
    payload = json.loads(result.stdout)
    run_dir = Path(payload["run_dir"])

    assert (run_dir / "request.json").exists()
    assert (run_dir / "metrics.json").exists()
    assert (run_dir / "prompt.json").exists()
    assert Path(payload["leaderboard"]).exists()
