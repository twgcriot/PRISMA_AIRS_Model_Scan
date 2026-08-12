"""Safe local filesystem listing and model-directory inventory for the scan console."""

from __future__ import annotations

from pathlib import Path
from typing import Any

_MAX_TREE_FILES = 400
_SKIP_DIR_NAMES = {".git", "__pycache__", ".venv", "venv", "node_modules"}

_FORMAT_BY_SUFFIX = {
    ".safetensors": "safetensors",
    ".json": "json",
    ".bin": "bin",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".ckpt": "pytorch",
    ".onnx": "onnx",
    ".gguf": "gguf",
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".h5": "hdf5",
    ".pb": "protobuf",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".index.json": "safetensors_index",
}


def allowed_roots() -> list[Path]:
    roots = [Path.cwd().resolve(), Path.home().resolve()]
    # Deduplicate if cwd is under home (or vice versa) — keep both; is_allowed uses any.
    out: list[Path] = []
    seen: set[Path] = set()
    for r in roots:
        if r not in seen:
            out.append(r)
            seen.add(r)
    return out


def resolve_allowed(path: str | Path) -> Path:
    raw = Path(path).expanduser()
    resolved = raw.resolve()
    if not any(_is_relative_to(resolved, root) for root in allowed_roots()):
        raise PermissionError(f"path is outside allowed roots: {resolved}")
    return resolved


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def format_for_name(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith(".safetensors.index.json") or lower.endswith("model.safetensors.index.json"):
        return "safetensors_index"
    suffix = Path(name).suffix.lower()
    return _FORMAT_BY_SUFFIX.get(suffix)


def list_dir(path: Path) -> dict[str, Any]:
    if not path.is_dir():
        raise NotADirectoryError(str(path))
    entries: list[dict[str, Any]] = []
    try:
        children = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except OSError as exc:
        raise PermissionError(str(exc)) from exc
    for child in children:
        try:
            is_dir = child.is_dir()
        except OSError:
            continue
        item: dict[str, Any] = {
            "name": child.name,
            "path": str(child),
            "type": "dir" if is_dir else "file",
        }
        if not is_dir:
            try:
                item["size"] = child.stat().st_size
            except OSError:
                item["size"] = None
            item["format"] = format_for_name(child.name)
        entries.append(item)
    parent = path.parent if path.parent != path else None
    parent_allowed = False
    if parent is not None:
        try:
            resolve_allowed(parent)
            parent_allowed = parent.is_dir()
        except (PermissionError, OSError):
            parent_allowed = False
    return {
        "path": str(path),
        "parent": str(parent) if parent_allowed else None,
        "entries": entries,
        "roots": [str(r) for r in allowed_roots()],
    }


def inventory(path: Path, *, max_files: int = _MAX_TREE_FILES) -> dict[str, Any]:
    """Walk a model directory: counts, bytes, formats, and a capped tree."""
    if not path.is_dir():
        raise NotADirectoryError(str(path))

    file_count = 0
    dir_count = 0
    total_bytes = 0
    truncated = False
    formats: dict[str, int] = {}

    def walk(dir_path: Path, rel: str) -> dict[str, Any]:
        nonlocal file_count, dir_count, total_bytes, truncated
        node: dict[str, Any] = {
            "name": dir_path.name or str(dir_path),
            "path": str(dir_path),
            "rel": rel,
            "type": "dir",
            "children": [],
            "size": 0,
        }
        try:
            children = sorted(dir_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except OSError:
            return node
        for child in children:
            try:
                is_dir = child.is_dir()
            except OSError:
                continue
            child_rel = child.name if not rel else f"{rel}/{child.name}"
            if is_dir:
                if child.name in _SKIP_DIR_NAMES:
                    continue
                dir_count += 1
                child_node = walk(child, child_rel)
                node["size"] += child_node.get("size") or 0
                node["children"].append(child_node)
                continue
            file_count += 1
            try:
                size = child.stat().st_size
            except OSError:
                size = 0
            total_bytes += size
            node["size"] += size
            fmt = format_for_name(child.name)
            if fmt:
                formats[fmt] = formats.get(fmt, 0) + 1
            if file_count <= max_files:
                node["children"].append(
                    {
                        "name": child.name,
                        "path": str(child),
                        "rel": child_rel,
                        "type": "file",
                        "size": size,
                        "format": fmt,
                    }
                )
            else:
                truncated = True
        return node

    tree = walk(path, "")
    return {
        "path": str(path),
        "name": path.name,
        "file_count": file_count,
        "dir_count": dir_count,
        "total_bytes": total_bytes,
        "formats": dict(sorted(formats.items(), key=lambda kv: (-kv[1], kv[0]))),
        "truncated": truncated,
        "tree": tree,
    }


def try_inventory(model_uri: str | None) -> dict[str, Any] | None:
    if not model_uri:
        return None
    raw = Path(model_uri).expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    try:
        resolved = resolve_allowed(raw)
    except (PermissionError, OSError):
        return None
    if not resolved.is_dir():
        return None
    try:
        return inventory(resolved)
    except OSError:
        return None
