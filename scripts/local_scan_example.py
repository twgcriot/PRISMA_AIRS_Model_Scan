#!/usr/bin/env python3
"""
Minimal Python example for scanning a local model directory.

This script loads Prisma AIRS credentials from a dotenv file, then calls:
  model-security scan --security-group-uuid ... --model-path ...
"""

from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv


def load_env(explicit_file: Path | None) -> None:
    if explicit_file is not None:
        env_path = explicit_file.expanduser()
        if not env_path.is_file():
            raise SystemExit(f"env file not found: {env_path}")
        load_dotenv(env_path, override=False)
        return

    for candidate in (
        Path(".env"),
        Path("model-security.env"),
        Path("config") / "model-security.env",
    ):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Example Python script to scan a local model directory with Prisma AIRS.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Optional dotenv path. If omitted, tries .env, model-security.env, config/model-security.env.",
    )
    parser.add_argument(
        "--security-group-uuid",
        required=True,
        help="Security group UUID for a LOCAL source type.",
    )
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Repeatable scan label passed as -l KEY=VALUE.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the command without executing it.",
    )
    parser.add_argument(
        "model_dir",
        type=Path,
        help="Local model directory path to scan.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    load_env(args.env_file)

    model_security = shutil.which("model-security")
    if not model_security:
        print(
            "model-security was not found on PATH. Activate your virtualenv or install model-security-client.",
            file=sys.stderr,
        )
        return 127

    model_dir = args.model_dir.expanduser().resolve()
    if not model_dir.is_dir():
        print(f"not a directory: {model_dir}", file=sys.stderr)
        return 2

    cmd = [
        model_security,
        "scan",
        "--security-group-uuid",
        args.security_group_uuid,
        "--model-path",
        str(model_dir),
    ]
    for label in args.label:
        if "=" not in label:
            print(f"invalid label {label!r}; expected KEY=VALUE", file=sys.stderr)
            return 2
        cmd.extend(["-l", label])

    if args.dry_run:
        print(shlex.join(cmd))
        return 0

    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
