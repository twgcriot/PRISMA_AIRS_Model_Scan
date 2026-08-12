"""Shared Data Plane fetch helpers for PDF reports and the local scan console.

API reference: https://pan.dev/prisma-airs-model-security/api/aisecuritymodel/aisecuritymodel/
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from uuid import UUID

from model_security_client.api import ModelSecurityAPIClient

# Data Plane validates limit <= 100 for /files, /rule-violations, /evaluations.
DATA_PLANE_PAGE_CAP = 100


def fetch_all_scans(
    client: ModelSecurityAPIClient,
    *,
    page_size: int,
    max_scans: int | None,
    security_group_uuid: UUID | None,
    source_types: list[Any] | None = None,
) -> tuple[list[Any], int | None]:
    scans: list[Any] = []
    skip = 0
    total_hint: int | None = None
    chunk = min(max(page_size, 1), DATA_PLANE_PAGE_CAP)

    while True:
        kwargs: dict[str, Any] = {
            "limit": chunk,
            "skip": skip,
            "sort_order": "desc",
            "security_group_uuid": security_group_uuid,
        }
        if source_types is not None:
            kwargs["source_types"] = source_types
        batch = client.list_scans(**kwargs)
        if total_hint is None and batch.pagination.total_items is not None:
            total_hint = batch.pagination.total_items
        scans.extend(batch.scans)
        if len(batch.scans) < chunk:
            break
        skip += chunk
        if max_scans is not None and len(scans) >= max_scans:
            return scans[:max_scans], total_hint

    return scans, total_hint


def fetch_all_scan_files(
    client: ModelSecurityAPIClient,
    scan_uuid: UUID,
    *,
    page_size: int = DATA_PLANE_PAGE_CAP,
) -> list[Any]:
    out: list[Any] = []
    skip = 0
    chunk = min(page_size, DATA_PLANE_PAGE_CAP)
    while True:
        batch = client.get_files(
            scan_uuid=scan_uuid,
            limit=chunk,
            skip=skip,
            query_path=None,
        )
        out.extend(batch.files)
        if len(batch.files) < chunk:
            break
        skip += chunk
    return out


def fetch_all_scan_violations(
    client: ModelSecurityAPIClient,
    scan_uuid: UUID,
    *,
    page_size: int = DATA_PLANE_PAGE_CAP,
) -> list[Any]:
    out: list[Any] = []
    skip = 0
    chunk = min(page_size, DATA_PLANE_PAGE_CAP)
    while True:
        batch = client.get_scan_violations(
            scan_uuid=scan_uuid,
            limit=chunk,
            skip=skip,
        )
        out.extend(batch.violations)
        if len(batch.violations) < chunk:
            break
        skip += chunk
    return out


def fetch_all_scan_evaluations(
    client: ModelSecurityAPIClient,
    scan_uuid: UUID,
    *,
    page_size: int = DATA_PLANE_PAGE_CAP,
) -> list[Any]:
    out: list[Any] = []
    skip = 0
    chunk = min(page_size, DATA_PLANE_PAGE_CAP)
    while True:
        batch = client.get_scan_evaluations(
            scan_uuid=scan_uuid,
            limit=chunk,
            skip=skip,
        )
        out.extend(batch.evaluations)
        if len(batch.evaluations) < chunk:
            break
        skip += chunk
    return out


def index_violations_by_file(violations: list[Any]) -> dict[str, list[Any]]:
    by_path: dict[str, list[Any]] = defaultdict(list)
    for v in violations:
        key = (getattr(v, "file", None) or "").strip()
        if not key:
            key = "__UNSPECIFIED__"
        by_path[key].append(v)
    return dict(by_path)


def viol_count_for_file(file_path: str, by_path: dict[str, list[Any]]) -> int:
    if file_path in by_path:
        return len(by_path[file_path])
    n = 0
    fp = file_path.rstrip("/")
    for vk, vs in by_path.items():
        if vk == "__UNSPECIFIED__":
            continue
        if vk == fp or fp.endswith(vk) or vk.endswith(fp):
            n += len(vs)
    return n


def to_jsonable(obj: Any) -> Any:
    """Serialize SDK pydantic models (and nested values) for JSON responses."""
    if obj is None:
        return None
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def scan_detail_payload(
    client: ModelSecurityAPIClient,
    scan: Any,
) -> dict[str, Any]:
    """Summary + evaluations + files + violations grouped by file."""
    evaluations = fetch_all_scan_evaluations(client, scan.uuid)
    files = fetch_all_scan_files(client, scan.uuid)
    violations = fetch_all_scan_violations(client, scan.uuid)
    by_path = index_violations_by_file(violations)
    files_json = to_jsonable(files)
    for f in files_json:
        path = f.get("path") or ""
        f["violation_count"] = viol_count_for_file(path, by_path)
    return {
        "scan": to_jsonable(scan),
        "evaluations": to_jsonable(evaluations),
        "files": files_json,
        "violations": to_jsonable(violations),
        "violations_by_file": {k: to_jsonable(vs) for k, vs in by_path.items()},
    }
