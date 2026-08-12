"""
Thin CLI around Palo Alto Prisma AIRS AI Model Security (`model-security`).

Install model-security-client from your tenant PyPI URL (see scripts/install-pan-model-security.sh
or scripts/fetch-pan-pypi-url.py), then set credentials via environment or a dotenv file
(see config/model-security.env.example).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv


def _load_model_security_env(explicit_file: Path | None) -> None:
    """Populate os.environ from a dotenv file (does not override existing vars)."""
    if explicit_file is not None:
        path = explicit_file.expanduser()
        if not path.is_file():
            print(f"env file not found: {path}", file=sys.stderr)
            sys.exit(2)
        load_dotenv(path, override=False)
        return

    override_path = os.environ.get("MODEL_SECURITY_ENV_FILE")
    if override_path:
        p = Path(override_path).expanduser()
        if p.is_file():
            load_dotenv(p, override=False)
        else:
            print(
                f"MODEL_SECURITY_ENV_FILE is set but not a file: {p}",
                file=sys.stderr,
            )
        return

    for candidate in (
        Path(".env"),
        Path("model-security.env"),
        Path("config") / "model-security.env",
    ):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            break


def _hf_model_uri(repo: str) -> str:
    repo = repo.strip().rstrip("/")
    if repo.startswith("https://huggingface.co/"):
        return repo
    if "/" not in repo:
        raise argparse.ArgumentTypeError(
            "Hugging Face repo must be 'org/name' or a full https://huggingface.co/... URL"
        )
    return f"https://huggingface.co/{repo}"


def _build_scan_argv(
    *,
    model_security_exe: str,
    security_group_uuid: str,
    model_path: str | None,
    model_uri: str | None,
    model_version: str | None,
    allow_patterns: list[str] | None,
    ignore_patterns: list[str] | None,
    extra: list[str],
) -> list[str]:
    argv = [model_security_exe, "scan", "--security-group-uuid", security_group_uuid]
    if model_path is not None:
        argv.extend(["--model-path", model_path])
    if model_uri is not None:
        argv.extend(["--model-uri", model_uri])
    if model_version is not None:
        argv.extend(["--model-version", model_version])
    for pat in allow_patterns or []:
        argv.extend(["--allow-patterns", pat])
    for pat in ignore_patterns or []:
        argv.extend(["--ignore-patterns", pat])
    argv.extend(extra)
    return argv


def _flatten_glob_groups(groups: list[list[str]] | None) -> list[str] | None:
    if not groups:
        return None
    flat = [p for grp in groups for p in grp]
    return flat or None


def _parse_labels(labels: list[str] | None) -> list[str]:
    out: list[str] = []
    if not labels:
        return out
    for item in labels:
        if "=" not in item:
            raise argparse.ArgumentTypeError(f"label must be key=value, got {item!r}")
        out.extend(["-l", item])
    return out


def _find_model_security() -> str | None:
    found = shutil.which("model-security")
    if found:
        return found
    # Do not resolve sys.executable first: venv python is often a symlink into Homebrew.
    sibling = Path(sys.executable).parent / "model-security"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return str(sibling)
    return None


def _model_security_version(exe: str) -> str | None:
    try:
        p = subprocess.run(
            [exe, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if p.returncode != 0:
            return None
        return (p.stdout or p.stderr or "").strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _cmd_doctor() -> int:
    """Print readiness checks; exit 0 if scan prerequisites look satisfied."""
    print("airs-modelscan / Prisma AIRS Model Security — environment check\n")

    ok = True
    exe = _find_model_security()
    if exe:
        ver = _model_security_version(exe)
        extra = f" ({ver})" if ver else ""
        print(f"  [ok]   model-security CLI: {exe}{extra}")
    else:
        ok = False
        print("  [fail] model-security CLI: not on PATH (install model-security-client in this venv)")

    def _var(name: str, required: bool) -> None:
        nonlocal ok
        val = os.environ.get(name, "").strip()
        if val:
            print(f"  [ok]   {name}: set")
        elif required:
            ok = False
            print(f"  [fail] {name}: not set")
        else:
            print(f"  [info] {name}: not set (optional)")

    _var("MODEL_SECURITY_CLIENT_ID", required=True)
    _var("MODEL_SECURITY_CLIENT_SECRET", required=True)
    _var("TSG_ID", required=True)
    _var("MODEL_SECURITY_API_ENDPOINT", required=False)
    _var("MODEL_SECURITY_PYPI_URL", required=False)

    try:
        from model_security_client.api import ModelSecurityAPIClient  # noqa: F401

        print("  [ok]   Python SDK: model_security_client importable")
    except ImportError:
        ok = False
        print("  [fail] Python SDK: model_security_client not importable")

    print()
    if ok:
        print("Ready to run scans (use a security group UUID that matches your model source).")
        return 0
    print("Fix the items marked [fail], then run `airs-modelscan doctor` again.")
    return 1


def _cmd_report_pdf(args: argparse.Namespace) -> int:
    try:
        from model_security_client.api import ModelSecurityAPIClient
    except ImportError:
        print(
            "model_security_client is not installed. Install model-security-client from your tenant PyPI.",
            file=sys.stderr,
        )
        return 127

    from prisma_airs_modelscan.pdf_report import write_scans_pdf
    from prisma_airs_modelscan.scans import fetch_all_scans

    base = os.environ.get("MODEL_SECURITY_API_ENDPOINT", "").rstrip("/")
    if not base:
        print(
            "MODEL_SECURITY_API_ENDPOINT is not set (see config/model-security.env.example).",
            file=sys.stderr,
        )
        return 2

    sg: UUID | None = None
    if getattr(args, "security_group_uuid", None):
        try:
            sg = UUID(args.security_group_uuid.strip())
        except ValueError:
            print("Invalid --security-group-uuid (expected UUID).", file=sys.stderr)
            return 2

    client = ModelSecurityAPIClient(base_url=base)
    scans, total_hint = fetch_all_scans(
        client,
        page_size=args.page_size,
        max_scans=args.max_scans,
        security_group_uuid=sg,
    )
    write_scans_pdf(
        args.output,
        scans,
        base_url=base,
        total_items_hint=total_hint,
        include_evaluations=bool(args.include_evaluations),
        client=client,
    )
    print(args.output.resolve())
    return 0


_LOCALHOST_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _cmd_ui(args: argparse.Namespace) -> int:
    host = (args.host or "127.0.0.1").strip()
    if host not in _LOCALHOST_HOSTS:
        print("The scan console binds localhost only (127.0.0.1 / localhost / ::1).", file=sys.stderr)
        return 2
    try:
        import uvicorn
    except ImportError:
        print(
            "UI extras are not installed. Run: pip install -e '.[ui]'",
            file=sys.stderr,
        )
        return 127
    try:
        from prisma_airs_modelscan.web.app import create_app
    except ImportError as exc:
        print(f"Could not load the scan console: {exc}", file=sys.stderr)
        print("Install UI extras with: pip install -e '.[ui]'", file=sys.stderr)
        return 127

    app = create_app()
    url = f"http://127.0.0.1:{args.port}/"
    print(f"Local scan console: {url}")
    if args.open_browser:
        import webbrowser

        webbrowser.open(url)
    uvicorn.run(app, host=host, port=args.port, log_level="info")
    return 0


def main(argv: list[str] | None = None) -> None:
    raw = sys.argv[1:] if argv is None else argv
    if "--" in raw:
        dd = raw.index("--")
        parse_argv, passthrough = raw[:dd], raw[dd + 1 :]
    else:
        parse_argv, passthrough = raw, []

    parser = argparse.ArgumentParser(
        prog="airs-modelscan",
        description="Run Prisma AIRS model scans for a local path or Hugging Face repo via model-security.",
        epilog="Use a bare -- before any extra flags you want forwarded to model-security scan.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="Load model-security variables from this dotenv file. "
        "If omitted, uses MODEL_SECURITY_ENV_FILE or the first of .env, model-security.env, config/model-security.env.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "doctor",
        help="Check PATH, credentials env vars, and Python SDK import.",
    )

    p_report = sub.add_parser(
        "report-pdf",
        help="Export scan history as a columnar PDF (Data Plane list_scans API).",
    )
    p_report.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("scans-report.pdf"),
        help="Output PDF path (default: scans-report.pdf).",
    )
    p_report.add_argument(
        "--page-size",
        type=int,
        default=100,
        metavar="N",
        help="Page size when calling list_scans (default: 100).",
    )
    p_report.add_argument(
        "--max-scans",
        type=int,
        default=None,
        metavar="N",
        help="Stop after this many scans (default: all pages).",
    )
    p_report.add_argument(
        "--security-group-uuid",
        type=str,
        default=None,
        metavar="UUID",
        help="If set, only include scans for this security group.",
    )
    p_report.add_argument(
        "--include-evaluations",
        action="store_true",
        help="Include per-scan rule evaluation table on detail pages (files + violations are "
        "always included; this adds get_scan_evaluations calls).",
    )

    p_local = sub.add_parser("local", help="Scan a model directory on disk.")
    p_local.add_argument(
        "--security-group-uuid",
        required=True,
        help="Security group UUID (must match local disk source type).",
    )
    p_local.add_argument(
        "path",
        type=Path,
        help="Directory containing the model (passed as --model-path).",
    )
    p_local.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the model-security command and exit without running it.",
    )
    p_local.add_argument(
        "-l",
        "--label",
        action="append",
        dest="labels",
        metavar="KEY=VALUE",
        help="Repeatable; forwarded as -l KEY=VALUE to model-security.",
    )

    p_hf = sub.add_parser("hf", help="Scan a public Hugging Face model repo.")
    p_hf.add_argument(
        "--security-group-uuid",
        required=True,
        help="Security group UUID (must match Hugging Face source type).",
    )
    p_hf.add_argument(
        "repo",
        type=str,
        help="org/name or full https://huggingface.co/org/name URL.",
    )
    p_hf.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the model-security command and exit without running it.",
    )
    p_hf.add_argument(
        "--revision",
        "--model-version",
        dest="model_version",
        metavar="REV",
        help="Optional HF revision (commit hash) to pin the scan.",
    )
    p_hf.add_argument(
        "--allow-patterns",
        nargs="+",
        action="append",
        metavar="GLOB",
        help="Include only these globs (HF scans only). Repeat the flag or pass multiple globs: "
        "--allow-patterns '*.bin' '*.json'.",
    )
    p_hf.add_argument(
        "--ignore-patterns",
        nargs="+",
        action="append",
        metavar="GLOB",
        help="Exclude these globs (HF scans only). Same usage as --allow-patterns.",
    )
    p_hf.add_argument(
        "-l",
        "--label",
        action="append",
        dest="labels",
        metavar="KEY=VALUE",
        help="Repeatable; forwarded as -l KEY=VALUE to model-security.",
    )

    p_ui = sub.add_parser(
        "ui",
        help="Open a localhost browser console for scanning a local model directory.",
    )
    p_ui.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (localhost only; default 127.0.0.1).",
    )
    p_ui.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port (default 8765).",
    )
    p_ui.add_argument(
        "--open",
        dest="open_browser",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Open the console in a browser (default: open). Use --no-open to skip.",
    )

    args = parser.parse_args(parse_argv)
    _load_model_security_env(args.env_file)

    if args.command == "doctor":
        raise SystemExit(_cmd_doctor())
    if args.command == "report-pdf":
        raise SystemExit(_cmd_report_pdf(args))
    if args.command == "ui":
        raise SystemExit(_cmd_ui(args))

    extra = list(passthrough)
    label_args = _parse_labels(getattr(args, "labels", None))

    exe = _find_model_security()
    if not exe and not args.dry_run:
        print(
            "model-security not found on PATH. Install AI Model Security (model-security-client) "
            "from your tenant PyPI URL per Palo Alto documentation.",
            file=sys.stderr,
        )
        sys.exit(127)
    model_security_exe = exe or "model-security"

    if args.command not in ("local", "hf"):
        parser.error(f"unknown command: {args.command!r}")

    if args.command == "local":
        path = args.path.expanduser().resolve()
        if not path.is_dir():
            parser.error(f"not a directory: {path}")
        scan_argv = _build_scan_argv(
            model_security_exe=model_security_exe,
            security_group_uuid=args.security_group_uuid,
            model_path=os.fspath(path),
            model_uri=None,
            model_version=None,
            allow_patterns=None,
            ignore_patterns=None,
            extra=label_args + extra,
        )
    else:
        uri = _hf_model_uri(args.repo)
        scan_argv = _build_scan_argv(
            model_security_exe=model_security_exe,
            security_group_uuid=args.security_group_uuid,
            model_path=None,
            model_uri=uri,
            model_version=args.model_version,
            allow_patterns=_flatten_glob_groups(getattr(args, "allow_patterns", None)),
            ignore_patterns=_flatten_glob_groups(getattr(args, "ignore_patterns", None)),
            extra=label_args + extra,
        )

    if args.dry_run:
        print(subprocess.list2cmdline(scan_argv))
        return

    raise SystemExit(subprocess.call(scan_argv))


if __name__ == "__main__":
    main()
