#!/usr/bin/env python3
"""Initialize a non-destructive Tomcat enumeration runbook workspace."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize a Tomcat enumeration evidence workspace without overwriting files."
    )
    parser.add_argument("path", type=Path, help="Absolute path for the engagement run")
    parser.add_argument("--scope", required=True, help="Exact authorized targets and protocols")
    parser.add_argument("--timezone", default="UTC", help="IANA timezone, default: UTC")
    parser.add_argument("--operator", default="UNSPECIFIED", help="Operator or team identifier")
    return parser.parse_args()


def create_exclusive(path: Path, content: str, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    os.chmod(path, mode)


def validate_target(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("path must be absolute")
    if path == Path("/"):
        raise ValueError("refusing to initialize at filesystem root")
    if path.exists():
        raise ValueError("run path already exists; choose a new path")
    resolved = path.resolve(strict=False)
    if resolved == Path("/"):
        raise ValueError("resolved path may not be filesystem root")
    return resolved


def main() -> int:
    args = parse_args()
    try:
        run_path = validate_target(args.path)
        timezone = ZoneInfo(args.timezone)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    created_at = datetime.now(timezone).isoformat(timespec="seconds")
    directories = {
        run_path / "evidence": 0o750,
        run_path / "evidence" / "raw": 0o750,
        run_path / "evidence" / "sanitized": 0o750,
        run_path / "notes": 0o750,
        run_path / "restricted": 0o700,
        run_path / "restricted" / "evidence": 0o700,
    }

    try:
        run_path.mkdir(mode=0o750, parents=True, exist_ok=False)
        os.chmod(run_path, 0o750)
        for directory, mode in directories.items():
            directory.mkdir(mode=mode, parents=True, exist_ok=False)
            if directory.is_symlink():
                raise ValueError(f"refusing symlink directory: {directory}")
            os.chmod(directory, mode)

        metadata = {
            "created_at": created_at,
            "timezone": args.timezone,
            "operator": args.operator,
            "scope": args.scope,
            "status_vocabulary": ["EXECUTED", "EVALUATED — NOT EXECUTED"],
            "confidence_vocabulary": [
                "CONFIRMED",
                "INFERRED",
                "POTENTIAL",
                "UNVERIFIED",
            ],
        }
        files = {
            run_path / "metadata.json": (
                json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
                0o640,
            ),
            run_path / ".gitignore": ("restricted/\n", 0o640),
            run_path / "report.md": (
                "# Tomcat Enumeration Runbook\n\n"
                f"- Created: {created_at}\n"
                f"- Operator: {args.operator}\n"
                f"- Scope: {args.scope}\n\n"
                "## Executive summary\n\nPending.\n\n"
                "## Constraints and approvals\n\nPending.\n\n"
                "## Timeline\n\nPending.\n\n"
                "## Findings\n\nPending.\n\n"
                "## Limitations and next steps\n\nPending.\n",
                0o640,
            ),
            run_path / "restricted" / "credentials.jsonl": ("", 0o600),
        }

        created_files: list[str] = []
        for path, (content, mode) in files.items():
            create_exclusive(path, content, mode)
            created_files.append(str(path))

    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"initialized: {run_path}")
    for path in created_files:
        print(f"created: {path}")
    print("restricted credentials mode: 0600")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
