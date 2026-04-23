#!/usr/bin/env python3
"""Run lint/typecheck/test/security checks across all repositories in a GitHub org."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import shlex
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


@dataclass
class CommandResult:
    command: str
    return_code: int
    stdout: str
    stderr: str


@dataclass
class RepoReview:
    name: str
    path: str
    checks: List[CommandResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class RepoSyncError(RuntimeError):
    """Raised when git clone/fetch/reset fails for a repository."""

    def __init__(self, message: str, result: CommandResult):
        super().__init__(message)
        self.result = result


def run_command(command: str, cwd: Path, timeout_seconds: int) -> CommandResult:
    process = subprocess.run(
        command,
        cwd=str(cwd),
        shell=True,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    return CommandResult(
        command=command,
        return_code=process.returncode,
        stdout=process.stdout.strip(),
        stderr=process.stderr.strip(),
    )


def github_request(url: str, token: Optional[str]) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "org-repo-review"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(url, headers=headers)
    with urlopen(request, timeout=30) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def iter_org_repos(org: str, token: Optional[str]) -> Iterable[dict]:
    page = 1
    while True:
        query = urlencode({"per_page": 100, "page": page, "type": "all"})
        url = f"https://api.github.com/orgs/{org}/repos?{query}"
        payload = github_request(url, token)
        if not payload:
            break
        for repo in payload:
            yield repo
        page += 1


def resolve_repo_checks(repo_path: Path) -> List[str]:
    package_json = repo_path / "package.json"
    bun_lock = repo_path / "bun.lockb"
    pnpm_lock = repo_path / "pnpm-lock.yaml"
    yarn_lock = repo_path / "yarn.lock"

    checks: List[str] = []
    if package_json.exists():
        if bun_lock.exists():
            checks.append("bun install")
            checks.extend(
                ["bun run lint", "bun run format", "bun run typecheck", "bun test"]
            )
        elif pnpm_lock.exists():
            checks.append("pnpm install --frozen-lockfile")
            checks.extend(
                [
                    "pnpm run lint",
                    "pnpm run format",
                    "pnpm run typecheck",
                    "pnpm run test",
                ]
            )
        elif yarn_lock.exists():
            checks.append("yarn install --frozen-lockfile")
            checks.extend(
                [
                    "yarn run lint",
                    "yarn run format",
                    "yarn run typecheck",
                    "yarn run test",
                ]
            )
        else:
            checks.append("npm ci")
            checks.extend(
                ["npm run lint", "npm run format", "npm run typecheck", "npm run test"]
            )

    if (repo_path / "pyproject.toml").exists() or (
        repo_path / "requirements.txt"
    ).exists():
        checks.extend(["python -m pip install -r requirements.txt", "python -m pytest"])

    if (repo_path / "foundry.toml").exists():
        checks.extend(["forge test", "slither ."])

    if (repo_path / "hardhat.config.ts").exists() or (
        repo_path / "hardhat.config.js"
    ).exists():
        checks.extend(["npx hardhat test", "npm audit --production"])

    return checks


def build_clone_url(repo_url: str, token: Optional[str]) -> str:
    if not token:
        return repo_url
    parsed_url = urlsplit(repo_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        return repo_url
    token_netloc = f"x-access-token:{quote(token, safe='')}@{parsed_url.netloc}"
    return urlunsplit(
        (
            parsed_url.scheme,
            token_netloc,
            parsed_url.path,
            parsed_url.query,
            parsed_url.fragment,
        )
    )


def clone_or_update_repo(repo_url: str, destination: Path, token: Optional[str]) -> None:
    if destination.exists() and (destination / ".git").exists():
        fetch_result = run_command(
            "git fetch --all --prune", destination, timeout_seconds=180
        )
        if fetch_result.return_code != 0:
            raise RepoSyncError("Failed to fetch latest refs.", fetch_result)
        reset_result = run_command(
            "git reset --hard origin/HEAD", destination, timeout_seconds=180
        )
        if reset_result.return_code != 0:
            raise RepoSyncError("Failed to reset repository to origin/HEAD.", reset_result)
        return

    if destination.exists():
        shutil.rmtree(destination)

    destination.parent.mkdir(parents=True, exist_ok=True)
    authenticated_repo_url = build_clone_url(repo_url, token)
    clone_result = run_command(
        f"git clone --depth 1 {shlex.quote(authenticated_repo_url)} {shlex.quote(str(destination))}",
        destination.parent,
        timeout_seconds=300,
    )
    if clone_result.return_code != 0:
        raise RepoSyncError("Failed to clone repository.", clone_result)


def write_reports(output_dir: Path, reviews: List[RepoReview]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "org-review.json"
    json_payload: List[Dict[str, object]] = []
    for review in reviews:
        json_payload.append(
            {
                "name": review.name,
                "path": review.path,
                "warnings": review.warnings,
                "checks": [asdict(check) for check in review.checks],
            }
        )
    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    md_path = output_dir / "org-review.md"
    lines = ["# Organisation Review Summary", ""]
    for review in reviews:
        lines.append(f"## {review.name}")
        lines.append(f"- Path: `{review.path}`")
        if review.warnings:
            for warning in review.warnings:
                lines.append(f"- ⚠️ {warning}")
        for check in review.checks:
            icon = "✅" if check.return_code == 0 else "❌"
            lines.append(f"- {icon} `{check.command}` (exit: {check.return_code})")
        lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", required=True, help="GitHub organisation name.")
    parser.add_argument(
        "--workspace",
        default=".cache/org-repos",
        help="Directory where repositories will be cloned/updated.",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Directory where JSON/Markdown reports are written.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Timeout in seconds for each command.",
    )
    parser.add_argument(
        "--repo-limit",
        type=int,
        default=0,
        help="Limit processed repos (0 = all).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.environ.get("GITHUB_TOKEN")

    try:
        repos = list(iter_org_repos(args.org, token))
    except (HTTPError, URLError) as exc:
        print(
            "Failed to list organisation repositories. "
            "Set GITHUB_TOKEN with access to the organisation and retry.",
            file=sys.stderr,
        )
        print(str(exc), file=sys.stderr)
        return 1

    if args.repo_limit > 0:
        repos = repos[: args.repo_limit]

    if not repos:
        print("No repositories found for the organisation.")
        return 0

    workspace = Path(args.workspace).resolve()
    reviews: List[RepoReview] = []
    had_sync_failures = False

    for repo in repos:
        repo_name = repo["name"]
        clone_url = repo["clone_url"]
        repo_path = workspace / repo_name

        review = RepoReview(name=repo_name, path=str(repo_path))
        try:
            clone_or_update_repo(clone_url, repo_path, token)
        except RepoSyncError as exc:
            had_sync_failures = True
            review.warnings.append(f"{exc} Git output: {exc.result.stderr or exc.result.stdout}")
            reviews.append(review)
            continue

        checks = resolve_repo_checks(repo_path)
        if not checks:
            review.warnings.append("No known checks detected for this repository.")

        for command in checks:
            if (
                "requirements.txt" in command
                and not (repo_path / "requirements.txt").exists()
            ):
                review.warnings.append(
                    "Skipped Python requirements install: requirements.txt missing."
                )
                continue
            try:
                result = run_command(command, repo_path, timeout_seconds=args.timeout)
            except subprocess.TimeoutExpired:
                review.checks.append(
                    CommandResult(
                        command=command,
                        return_code=124,
                        stdout="",
                        stderr=f"Command timed out after {args.timeout} seconds.",
                    )
                )
                continue
            review.checks.append(result)

        reviews.append(review)

    write_reports(Path(args.output), reviews)
    print(f"Review completed for {len(reviews)} repositories.")
    print(f"Reports written to: {Path(args.output).resolve()}")
    if had_sync_failures:
        print(
            "One or more repositories could not be cloned or updated. "
            "See warnings in the report for details.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
