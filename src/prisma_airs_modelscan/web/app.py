"""Localhost FastAPI app for the Prisma AIRS local model scan console."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from prisma_airs_modelscan.cli import _find_model_security, _model_security_version
from prisma_airs_modelscan.web.fsutil import inventory, list_dir, resolve_allowed
from prisma_airs_modelscan.web.hfutil import HfError, list_downloaded_models, search_public_models
from prisma_airs_modelscan.web.jobs import JobStore, ScanBusyError
from prisma_airs_modelscan.web.native import (
    NativeCliError,
    list_group_rule_instances,
    list_local_security_groups,
)

STATIC_DIR = Path(__file__).parent / "static"


class DownloadStartRequest(BaseModel):
    hf_repo: str
    hf_revision: str | None = None


class ScanStartRequest(BaseModel):
    path: str
    security_group_uuid: str


def _health_payload() -> dict[str, Any]:
    checks: dict[str, Any] = {}
    ok = True
    exe = _find_model_security()
    if exe:
        checks["model_security_cli"] = {
            "ok": True,
            "path": exe,
            "version": _model_security_version(exe),
        }
    else:
        ok = False
        checks["model_security_cli"] = {"ok": False, "path": None, "version": None}

    for name, required in (
        ("MODEL_SECURITY_CLIENT_ID", True),
        ("MODEL_SECURITY_CLIENT_SECRET", True),
        ("TSG_ID", True),
        ("MODEL_SECURITY_API_ENDPOINT", False),
    ):
        present = bool(os.environ.get(name, "").strip())
        checks[name] = {"ok": present if required else True, "set": present}
        if required and not present:
            ok = False

    try:
        import huggingface_hub  # noqa: F401

        checks["huggingface_hub"] = {"ok": True}
    except ImportError:
        checks["huggingface_hub"] = {"ok": False}

    return {"ok": ok, "checks": checks}


def create_app() -> FastAPI:
    store = JobStore()
    app = FastAPI(title="Prisma AIRS local scan console", docs_url=None, redoc_url=None)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return _health_payload()

    @app.get("/api/fs")
    def fs_browse(
        path: str | None = None,
        mode: str = Query(default="list", pattern="^(list|preview)$"),
    ) -> dict[str, Any]:
        target = Path(path).expanduser() if path else Path.cwd()
        try:
            resolved = resolve_allowed(target)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        if not resolved.exists():
            raise HTTPException(status_code=404, detail=f"not found: {resolved}")
        try:
            if mode == "preview":
                if not resolved.is_dir():
                    raise HTTPException(status_code=400, detail="preview requires a directory")
                return inventory(resolved)
            if not resolved.is_dir():
                raise HTTPException(status_code=400, detail="not a directory")
            return list_dir(resolved)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except NotADirectoryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/hf/models")
    def hf_search(
        q: str = Query(..., min_length=1),
        limit: int = Query(default=20, ge=1, le=50),
    ) -> dict[str, Any]:
        try:
            models = search_public_models(q, limit=limit)
        except HfError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"Hugging Face Hub error: {exc}") from exc
        return {"query": q, "models": models}

    @app.get("/api/models")
    def local_models() -> dict[str, Any]:
        return {"models": list_downloaded_models()}

    @app.get("/api/security-groups")
    def security_groups() -> dict[str, Any]:
        try:
            return list_local_security_groups()
        except NativeCliError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/security-groups/{security_group_uuid}/rules")
    def security_group_rules(security_group_uuid: UUID) -> dict[str, Any]:
        try:
            rules = list_group_rule_instances(str(security_group_uuid))
        except NativeCliError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"security_group_uuid": str(security_group_uuid), "rules": rules}

    @app.post("/api/downloads", status_code=202)
    def start_download(body: DownloadStartRequest) -> JSONResponse:
        repo = (body.hf_repo or "").strip()
        if not repo:
            raise HTTPException(status_code=400, detail="hf_repo is required")
        try:
            job = store.start_download(
                hf_repo=repo,
                hf_revision=(body.hf_revision or "").strip() or None,
            )
        except ScanBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (HfError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(job.snapshot(), status_code=202)

    @app.post("/api/scans", status_code=202)
    def start_scan(body: ScanStartRequest) -> JSONResponse:
        path = (body.path or "").strip()
        if not path:
            raise HTTPException(status_code=400, detail="path is required")
        try:
            UUID(body.security_group_uuid.strip())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid security_group_uuid") from exc
        try:
            job = store.start_scan(
                model_path=path,
                security_group_uuid=body.security_group_uuid.strip(),
            )
        except ScanBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except NotADirectoryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(job.snapshot(), status_code=202)

    @app.get("/api/jobs/{job_id}/events")
    async def job_events(job_id: str) -> EventSourceResponse:
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")

        async def gen():
            idx = 0
            while True:
                with job.lock:
                    batch = job.events[idx:]
                    finished = job.finished
                for event in batch:
                    idx += 1
                    yield {
                        "event": event.get("type") or "message",
                        "data": json.dumps(event),
                    }
                if finished and idx >= len(job.events):
                    break
                await asyncio.sleep(0.12)

        return EventSourceResponse(gen())

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app
