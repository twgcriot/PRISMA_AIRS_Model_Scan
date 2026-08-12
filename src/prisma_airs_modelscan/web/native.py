"""Run the vendor `model-security` CLI and parse JSON from its stdout.

The console uses this instead of the Python SDK / REST client.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from prisma_airs_modelscan.cli import _find_model_security

_PAGE = 100


class NativeCliError(RuntimeError):
    pass


def extract_last_json(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    last: dict[str, Any] | None = None
    i = 0
    while True:
        j = text.find("{", i)
        if j < 0:
            break
        try:
            obj, end = decoder.raw_decode(text, j)
        except json.JSONDecodeError:
            i = j + 1
            continue
        if isinstance(obj, dict):
            last = obj
        i = end
    return last


def run_cli(*args: str) -> dict[str, Any]:
    exe = _find_model_security()
    if not exe:
        raise NativeCliError(
            "model-security not found. Install model-security-client in this environment."
        )
    cmd = [exe, "--log-level", "error", *args]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    text = (proc.stdout or "") + (proc.stderr or "")
    parsed = extract_last_json(text)
    if parsed is None:
        tail = text[-1500:] if text else f"exit {proc.returncode}"
        raise NativeCliError(f"model-security {' '.join(args[:4])} returned no JSON\n{tail}")
    return parsed


def _paginate(command: str, extra: list[str], list_key: str) -> list[Any]:
    out: list[Any] = []
    skip = 0
    while True:
        payload = run_cli(command, *extra, "--limit", str(_PAGE), "--skip", str(skip))
        batch = payload.get(list_key) or []
        out.extend(batch)
        total = (payload.get("pagination") or {}).get("total_items")
        if len(batch) < _PAGE:
            break
        skip += _PAGE
        if total is not None and skip >= int(total):
            break
    return out


def list_local_security_groups() -> dict[str, Any]:
    payload = run_cli(
        "list-security-groups",
        "--source-types",
        "LOCAL",
        "--limit",
        "50",
        "--skip",
        "0",
        "--sort-dir",
        "desc",
    )
    groups = payload.get("security_groups") or []
    default_uuid = None
    for g in groups:
        if str(g.get("name") or "").strip().lower() == "default local":
            default_uuid = g.get("uuid")
            break
    if default_uuid is None and groups:
        default_uuid = groups[0].get("uuid")
    return {"security_groups": groups, "default_uuid": default_uuid}


def list_group_rule_instances(security_group_uuid: str) -> list[dict[str, Any]]:
    raw = _paginate(
        "list-rule-instances",
        ["--security-group-uuid", security_group_uuid],
        "rule_instances",
    )
    rules: list[dict[str, Any]] = []
    for item in raw:
        rule = item.get("rule") or {}
        rules.append(
            {
                "uuid": item.get("uuid"),
                "state": item.get("state"),
                "security_rule_uuid": item.get("security_rule_uuid"),
                "rule_name": rule.get("name"),
                "rule_description": rule.get("description"),
                "rule_type": rule.get("rule_type"),
                "field_values": item.get("field_values") or {},
            }
        )
    return rules


def fetch_scan_evaluations(scan_uuid: str) -> dict[str, Any]:
    """Scan summary + every rule evaluation via native CLI (no files/violations)."""
    scan = run_cli("get-scan", "--uuid", scan_uuid)
    evaluations = _paginate(
        "get-scan-evaluations",
        ["--scan-uuid", scan_uuid],
        "evaluations",
    )
    return {"scan": scan, "evaluations": evaluations}
