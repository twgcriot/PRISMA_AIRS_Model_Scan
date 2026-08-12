"""Public Hugging Face Hub search and download helpers for the scan console."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$"
)


class HfError(RuntimeError):
    pass


def normalize_repo(raw: str) -> str:
    repo = (raw or "").strip().rstrip("/")
    if repo.startswith("https://huggingface.co/"):
        repo = repo[len("https://huggingface.co/") :]
    repo = repo.split("?")[0].split("#")[0].strip("/")
    if not _REPO_RE.match(repo):
        raise HfError("Hugging Face repo must look like org/model-name")
    return repo


def models_root() -> Path:
    return (Path.cwd() / "models").resolve()


def local_dir_for_repo(repo: str) -> Path:
    safe = repo.replace("/", "--")
    return (models_root() / safe).resolve()


def display_name_for_dir(name: str) -> str:
    return name.replace("--", "/", 1)


def dir_stats(path: Path) -> dict[str, int]:
    file_count = 0
    total_bytes = 0
    try:
        for item in path.rglob("*"):
            if not item.is_file():
                continue
            file_count += 1
            try:
                total_bytes += item.stat().st_size
            except OSError:
                pass
    except OSError:
        pass
    return {"file_count": file_count, "total_bytes": total_bytes}


def list_downloaded_models() -> list[dict[str, Any]]:
    root = models_root()
    if not root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        stats = dir_stats(child)
        out.append(
            {
                "id": child.name,
                "name": display_name_for_dir(child.name),
                "path": str(child),
                "file_count": stats["file_count"],
                "total_bytes": stats["total_bytes"],
            }
        )
    return out


def _is_public(info: Any) -> bool:
    if bool(getattr(info, "private", False)):
        return False
    gated = getattr(info, "gated", False)
    return not bool(gated)


def _model_dict(info: Any) -> dict[str, Any]:
    last = getattr(info, "last_modified", None) or getattr(info, "lastModified", None)
    return {
        "id": getattr(info, "id", None) or getattr(info, "modelId", None),
        "downloads": getattr(info, "downloads", None),
        "likes": getattr(info, "likes", None),
        "pipeline_tag": getattr(info, "pipeline_tag", None),
        "library_name": getattr(info, "library_name", None),
        "gated": bool(getattr(info, "gated", False)),
        "private": bool(getattr(info, "private", False)),
        "sha": getattr(info, "sha", None),
        "last_modified": last.isoformat() if hasattr(last, "isoformat") else last,
        "public": _is_public(info),
    }


def _api():
    try:
        from huggingface_hub import HfApi
    except ImportError as exc:
        raise HfError(
            "huggingface_hub is not installed. Run: pip install -e '.[ui]'"
        ) from exc
    return HfApi()


def search_public_models(query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    q = (query or "").strip()
    if not q:
        raise HfError("search query is required")
    api = _api()
    if "/" in q and " " not in q:
        try:
            repo = normalize_repo(q)
        except HfError:
            repo = None
        if repo:
            try:
                info = api.model_info(repo)
                row = _model_dict(info)
                if not row["public"]:
                    raise HfError(f"{repo} is private or gated; this console only downloads public models")
                return [row]
            except HfError:
                raise
            except Exception:
                pass

    cap = max(1, min(int(limit), 50))
    found: list[dict[str, Any]] = []
    iterator = api.list_models(
        search=q,
        sort="downloads",
        gated=False,
        limit=cap * 2,
    )
    for info in iterator:
        row = _model_dict(info)
        if not row["id"] or not row["public"]:
            continue
        found.append(row)
        if len(found) >= cap:
            break
    return found


def assert_public_repo(repo: str) -> dict[str, Any]:
    repo = normalize_repo(repo)
    api = _api()
    try:
        info = api.model_info(repo)
    except Exception as exc:  # noqa: BLE001
        raise HfError(f"could not load {repo}: {exc}") from exc
    row = _model_dict(info)
    if not row["public"]:
        raise HfError(f"{repo} is private or gated; this console only downloads public models")
    return row


def download_public_repo(repo: str, dest: Path, *, revision: str | None = None) -> Path:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise HfError(
            "huggingface_hub is not installed. Run: pip install -e '.[ui]'"
        ) from exc
    dest.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, Any] = {"repo_id": repo, "local_dir": str(dest)}
    if revision:
        kwargs["revision"] = revision
    snapshot_download(**kwargs)
    return dest
