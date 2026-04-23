#!/usr/bin/env python3
"""Build a constrained prompt for autonomous kernel patch generation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DEFAULT_SKILLS = [
    "skills/cuda.md",
    "skills/tiling.md",
    "skills/memory_coalescing.md",
]

FAILURE_SKILLS = {
    "benchmark_regression": ["skills/optimization_strategies.md"],
    "abi_break": ["skills/compatibility_rules.md"],
}


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def load_skills(root: Path, skill_paths: list[str]) -> str:
    parts: list[str] = []
    for skill_path in skill_paths:
        resolved = root / skill_path
        content = read_text(resolved)
        if not content:
            continue
        parts.append(f"# Skill: {resolved.name}\n{content}")
    return "\n\n".join(parts)


def format_memory(memory_root: Path) -> str:
    failure_patterns = read_json(memory_root / "failure_patterns.json")
    strategies = read_json(memory_root / "successful_strategies.json")
    if not failure_patterns and not strategies:
        return "No historical memory available."

    chunks: list[str] = []
    if failure_patterns:
        chunks.append("## Failure Patterns\n" + json.dumps(failure_patterns, indent=2))
    if strategies:
        chunks.append("## Successful Strategies\n" + json.dumps(strategies, indent=2))
    return "\n\n".join(chunks)


def build_prompt(
    issue: str,
    skills_text: str,
    constraints: str,
    failure_type: str,
    repair_strategy: str,
    performance_context: dict[str, Any],
    memory_context: str,
) -> str:
    sections = [
        "You are an autonomous kernel contributor.",
        "Generate a patch that is safe, minimal, and benchmark-aware.",
        "",
        "## Routing Context",
        f"- failure_type: {failure_type or 'unknown'}",
        f"- repair_strategy: {repair_strategy or 'unspecified'}",
        "",
        "## Kernel Constraints",
        constraints or "- Preserve API compatibility\n- Avoid perf regressions > 3%",
        "",
        "## Performance Context",
        json.dumps(performance_context or {"status": "missing"}, indent=2),
        "",
        "## Memory Context",
        memory_context,
        "",
        "## Loaded Skills",
        skills_text or "No skill files were provided.",
        "",
        "## Issue",
        issue,
        "",
        "## Required Output",
        "1) Unified diff patch",
        "2) Test plan",
        "3) Benchmark notes",
    ]
    return "\n".join(sections)


def resolve_skill_list(failure_type: str, skill_paths: list[str]) -> list[str]:
    extra = FAILURE_SKILLS.get(failure_type, [])
    merged = [*skill_paths, *extra]
    seen: set[str] = set()
    unique: list[str] = []
    for entry in merged:
        if entry in seen:
            continue
        seen.add(entry)
        unique.append(entry)
    return unique


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("issue_file", type=Path)
    parser.add_argument("--constraints", type=Path, default=Path("docs/pipelines/GATES.md"))
    parser.add_argument("--skills", nargs="*", default=DEFAULT_SKILLS)
    parser.add_argument("--out", type=Path, default=Path(".codex/prompt.json"))
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--memory-dir", type=Path, default=Path(".codex/memory"))
    args = parser.parse_args()

    issue_payload = read_json(args.issue_file)
    issue_text = read_text(args.issue_file)
    constraints_text = read_text(args.constraints)
    failure_type = issue_payload.get("failure_type", "")
    repair_strategy = issue_payload.get("repair_strategy", "")

    skill_list = resolve_skill_list(failure_type, args.skills)
    skills_text = load_skills(Path("."), skill_list)

    performance_context: dict[str, Any] = {}
    if args.run_dir:
        performance_context = read_json(args.run_dir / "metrics.json")

    memory_context = format_memory(args.memory_dir)
    prompt = build_prompt(
        issue=issue_payload.get("body", issue_text),
        skills_text=skills_text,
        constraints=constraints_text,
        failure_type=failure_type,
        repair_strategy=repair_strategy,
        performance_context=performance_context,
        memory_context=memory_context,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(
            {
                "prompt": prompt,
                "failure_type": failure_type,
                "repair_strategy": repair_strategy,
                "skills": skill_list,
                "performance_context": performance_context,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
