#!/usr/bin/env python3
"""Generate a tracked Codex run artifact from a GitHub issue payload.

This script is intentionally provider-agnostic: it prepares prompt payloads and
records execution context so teams can plug in their own Codex/OpenAI call.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FAILURE_TO_STRATEGY = {
    "benchmark_regression": "optimize",
    "compile_error": "fix_syntax",
    "abi_break": "restore_compat",
    "test_failure": "adjust_shape",
}


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def sanitize_slug(text: str) -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "-" for ch in text)
    squashed = "-".join(chunk for chunk in normalized.split("-") if chunk)
    return (squashed[:40] or "issue").strip("-")


def classify_failure(title: str, body: str) -> str:
    combined = f"{title}\n{body}".lower()
    if "benchmark" in combined or "latency" in combined or "throughput" in combined:
        return "benchmark_regression"
    if "abi" in combined or "compat" in combined:
        return "abi_break"
    if "syntax" in combined or "compile" in combined or "import error" in combined:
        return "compile_error"
    if "test" in combined or "assert" in combined:
        return "test_failure"
    return "test_failure"


def extract_taxonomy_from_body(body: str) -> dict[str, str]:
    match = re.search(r"```json\s*(\{.*?\})\s*```", body, flags=re.DOTALL)
    if not match:
        return {}
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}
    failure_type = str(payload.get("failure_type", "")).strip()
    repair_strategy = str(payload.get("repair_strategy", "")).strip()
    result: dict[str, str] = {}
    if failure_type in FAILURE_TO_STRATEGY:
        result["failure_type"] = failure_type
    if repair_strategy:
        result["repair_strategy"] = repair_strategy
    return result


def extract_issue(issue_payload: Path) -> dict[str, Any]:
    if issue_payload.suffix == ".json":
        payload = json.loads(issue_payload.read_text(encoding="utf-8"))
        title = payload.get("title", "Kernel improvement")
        body = payload.get("body", "No issue body provided.")
        taxonomy = extract_taxonomy_from_body(body)
        failure_type = payload.get("failure_type") or taxonomy.get("failure_type") or classify_failure(
            title, body
        )
        repair_strategy = (
            payload.get("repair_strategy")
            or taxonomy.get("repair_strategy")
            or FAILURE_TO_STRATEGY[failure_type]
        )
        return {
            "title": title,
            "body": body,
            "failure_type": failure_type,
            "repair_strategy": repair_strategy,
        }

    content = issue_payload.read_text(encoding="utf-8")
    lines = content.splitlines()
    title = lines[0] if lines else "Kernel improvement"
    body = "\n".join(lines[1:]).strip() or content
    failure_type = classify_failure(title, body)
    return {
        "title": title,
        "body": body,
        "failure_type": failure_type,
        "repair_strategy": FAILURE_TO_STRATEGY[failure_type],
    }


def write_patch_request(run_dir: Path, issue: dict[str, Any]) -> Path:
    constraints = (
        "- Keep ABI stable\n"
        "- Add/adjust tests for behavioral changes\n"
        "- Reject regressions above 3% in benchmark gates\n"
        "- Keep fallback path for CPU when GPU path changes"
    )
    request = {
        **issue,
        "constraints": constraints,
        "repository": os.getenv("GITHUB_REPOSITORY", "local"),
        "base_ref": os.getenv("GITHUB_REF_NAME", git("rev-parse", "--abbrev-ref", "HEAD")),
    }
    request_file = run_dir / "request.json"
    request_file.write_text(json.dumps(request, indent=2), encoding="utf-8")
    return request_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("issue_payload", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path(".codex/runs"))
    args = parser.parse_args()

    issue = extract_issue(args.issue_payload)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = sanitize_slug(issue["title"])
    run_dir = args.out_dir / f"{run_id}-{slug}"
    run_dir.mkdir(parents=True, exist_ok=True)

    request_file = write_patch_request(run_dir, issue)
    plan_file = run_dir / "plan.md"
    plan_file.write_text(
        "# Codex Patch Plan\n\n"
        "1. Reproduce issue with tests or benchmark baseline.\n"
        "2. Implement minimal patch preserving API/ABI assumptions.\n"
        "3. Run CI checks and benchmark guardrails.\n"
        "4. Summarize risk and rollout notes in the PR body.\n",
        encoding="utf-8",
    )

    print(f"codex_run_dir={run_dir}")
    print(f"codex_request={request_file}")


if __name__ == "__main__":
    main()
