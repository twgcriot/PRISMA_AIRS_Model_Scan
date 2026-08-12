"""One-at-a-time local scan jobs with SSE-friendly event logs."""

from __future__ import annotations

import os
import re
import select
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from prisma_airs_modelscan.cli import _find_model_security
from prisma_airs_modelscan.web.fsutil import resolve_allowed
from prisma_airs_modelscan.web.hfutil import assert_public_repo, dir_stats, local_dir_for_repo, normalize_repo
from prisma_airs_modelscan.web.native import extract_last_json, fetch_scan_evaluations

_STAGE_HINTS: list[tuple[str, str]] = [
    ("Scan initiated", "submit"),
    ("Model size calculated", "submit"),
    ("Submitting scan", "submit"),
    ("Scan submitted successfully", "evaluate"),
    ("Polling for scan outcome", "evaluate"),
    ("Scan complete", "enrich"),
]
_NOISE = (
    "UnsupportedFieldAttributeWarning",
    "warnings.warn(",
)
_ANSI_RE = re.compile(rb"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|].*?(?:\x07|\x1b\\)|[()][0-9A-Za-z])")


class ScanBusyError(RuntimeError):
    pass


def _find_bin(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    sibling = Path(sys.executable).parent / name
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return str(sibling)
    return None


def _noisy(line: str) -> bool:
    return any(token in line for token in _NOISE)


def _emit_cli_line(job: Job, line: str, overwrite: bool) -> None:
    if _noisy(line):
        return
    job.emit("log", stream="cli", line=line, overwrite=overwrite)
    for needle, stage in _STAGE_HINTS:
        if needle in line:
            job.emit("stage", stage=stage)
            break


def _split_stream(job: Job, buf: bytearray, chunk: bytes, collected: list[str]) -> None:
    """Split mixed \\n / \\r output so tqdm progress overwrites the last terminal line."""
    buf.extend(_ANSI_RE.sub(b"", chunk.replace(b"\x08", b"")))
    while True:
        npos = buf.find(b"\n")
        rpos = buf.find(b"\r")
        if npos < 0 and rpos < 0:
            break
        if npos >= 0 and (rpos < 0 or npos <= rpos):
            raw = bytes(buf[:npos])
            del buf[: npos + 1]
            overwrite = False
        else:
            raw = bytes(buf[:rpos])
            del buf[: rpos + 1]
            overwrite = True
            if buf.startswith(b"\n"):
                del buf[:1]
                overwrite = False
        line = raw.decode("utf-8", errors="replace")
        collected.append(line + "\n")
        if line:
            _emit_cli_line(job, line, overwrite)


def _stream_command(job: Job, argv: list[str]) -> tuple[str, int]:
    """Run a command in a PTY so download/scan progress streams like a real terminal."""
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("COLUMNS", "100")
    env.setdefault("TERM", "xterm-256color")
    collected: list[str] = []
    buf = bytearray()

    if hasattr(os, "openpty"):
        import fcntl
        import struct
        import termios

        master_fd, slave_fd = os.openpty()
        try:
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        except OSError:
            pass
        proc = subprocess.Popen(
            argv,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave_fd)
        try:
            while True:
                dead = proc.poll() is not None
                timeout = 0.0 if dead else 0.1
                ready, _, _ = select.select([master_fd], [], [], timeout)
                if ready:
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError:
                        chunk = b""
                    if chunk:
                        _split_stream(job, buf, chunk, collected)
                        continue
                if dead:
                    break
        finally:
            os.close(master_fd)
        if buf:
            line = buf.decode("utf-8", errors="replace")
            collected.append(line)
            if line:
                _emit_cli_line(job, line, overwrite=False)
        return "".join(collected), proc.wait()

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        bufsize=0,
    )
    assert proc.stdout is not None
    while True:
        chunk = proc.stdout.read(256)
        if not chunk:
            break
        _split_stream(job, buf, chunk, collected)
    if buf:
        line = buf.decode("utf-8", errors="replace")
        collected.append(line)
        if line:
            _emit_cli_line(job, line, overwrite=False)
    return "".join(collected), proc.wait()


class Job:
    def __init__(
        self,
        job_id: str,
        *,
        kind: str,
        model_path: str,
        security_group_uuid: str | None = None,
        hf_repo: str | None = None,
        hf_revision: str | None = None,
    ) -> None:
        self.id = job_id
        self.kind = kind
        self.model_path = model_path
        self.security_group_uuid = security_group_uuid
        self.hf_repo = hf_repo
        self.hf_revision = hf_revision
        self.events: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.finished = False
        self.scan_uuid: str | None = None
        self.error: str | None = None
        self.exit_code: int | None = None
        self.stage = "download" if kind == "download" else "scan"
        self.started_at = time.monotonic()
        self.duration_ms: int | None = None
        self.file_count: int | None = None
        self.total_bytes: int | None = None

    def emit(self, event_type: str, **payload: Any) -> None:
        event = {"type": event_type, **payload}
        with self.lock:
            self.events.append(event)
            if event_type == "stage":
                self.stage = str(payload.get("stage") or self.stage)
            if payload.get("scan_uuid"):
                self.scan_uuid = str(payload["scan_uuid"])

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "job_id": self.id,
                "kind": self.kind,
                "model_path": self.model_path,
                "hf_repo": self.hf_repo,
                "hf_revision": self.hf_revision,
                "security_group_uuid": self.security_group_uuid,
                "stage": self.stage,
                "finished": self.finished,
                "scan_uuid": self.scan_uuid,
                "error": self.error,
                "exit_code": self.exit_code,
                "duration_ms": self.duration_ms,
                "file_count": self.file_count,
                "total_bytes": self.total_bytes,
                "event_count": len(self.events),
            }


class JobStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._busy = False
        self._jobs: dict[str, Job] = {}
        self._current_id: str | None = None

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def _begin(self, job: Job) -> Job:
        with self._lock:
            if self._busy:
                raise ScanBusyError("a job is already running")
            self._busy = True
            self._jobs[job.id] = job
            self._current_id = job.id
        thread = threading.Thread(
            target=self._run, args=(job,), name=f"{job.kind}-job-{job.id[:8]}", daemon=True
        )
        thread.start()
        return job

    def start_download(self, *, hf_repo: str, hf_revision: str | None = None) -> Job:
        repo = normalize_repo(hf_repo)
        dest = local_dir_for_repo(repo)
        resolve_allowed(dest if dest.exists() else dest.parent)
        job = Job(
            str(uuid.uuid4()),
            kind="download",
            model_path=str(dest),
            hf_repo=repo,
            hf_revision=(hf_revision or "").strip() or None,
        )
        return self._begin(job)

    def start_scan(self, *, model_path: str, security_group_uuid: str) -> Job:
        path = resolve_allowed(model_path)
        if not path.is_dir():
            raise NotADirectoryError(str(path))
        job = Job(
            str(uuid.uuid4()),
            kind="scan",
            model_path=str(path),
            security_group_uuid=security_group_uuid,
        )
        return self._begin(job)

    def _finish(self, job: Job) -> None:
        with job.lock:
            job.finished = True
        with self._lock:
            if self._current_id == job.id:
                self._busy = False
                self._current_id = None

    def _run(self, job: Job) -> None:
        try:
            self._run_inner(job)
        except Exception as exc:  # noqa: BLE001
            job.error = str(exc)
            job.emit("fail", message=str(exc))
            job.emit("stage", stage="error")
        finally:
            job.duration_ms = int((time.monotonic() - job.started_at) * 1000)
            job.emit(
                "stats",
                duration_ms=job.duration_ms,
                file_count=job.file_count,
                total_bytes=job.total_bytes,
            )
            job.emit("done", scan_uuid=job.scan_uuid, error=job.error, exit_code=job.exit_code)
            self._finish(job)

    def _run_inner(self, job: Job) -> None:
        if job.kind == "download":
            self._run_download(job)
            return
        self._run_scan(job)

    def _run_download(self, job: Job) -> None:
        if not job.hf_repo:
            raise RuntimeError("hf_repo is required")
        job.emit("stage", stage="download")
        assert_public_repo(job.hf_repo)
        dest = Path(job.model_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        hf = _find_bin("hf")
        if not hf:
            raise RuntimeError("hf CLI not found. pip install huggingface_hub")
        argv = [hf, "download", job.hf_repo, "--local-dir", str(dest)]
        if job.hf_revision:
            argv.extend(["--revision", job.hf_revision])
        job.emit("log", stream="prompt", line="$ " + " ".join(argv))
        _text, code = _stream_command(job, argv)
        if code != 0:
            raise RuntimeError(f"hf download exited {code}")
        job.model_path = str(dest)
        stats = dir_stats(dest)
        job.file_count = stats["file_count"]
        job.total_bytes = stats["total_bytes"]
        job.emit("log", stream="meta", line=f"saved {dest}")
        job.emit("downloaded", path=str(dest), repo=job.hf_repo, **stats)
        job.emit("stage", stage="complete")

    def _run_scan(self, job: Job) -> None:
        if not job.security_group_uuid:
            raise RuntimeError("security_group_uuid is required")
        exe = _find_model_security()
        if not exe:
            raise RuntimeError(
                "model-security not found on PATH. Install model-security-client in this environment."
            )
        argv = [
            exe,
            "scan",
            "--security-group-uuid",
            job.security_group_uuid,
            "--model-path",
            job.model_path,
        ]
        job.emit("stage", stage="scan")
        stats = dir_stats(Path(job.model_path))
        job.file_count = stats["file_count"]
        job.total_bytes = stats["total_bytes"]
        job.emit(
            "stats",
            file_count=job.file_count,
            total_bytes=job.total_bytes,
        )
        job.emit("log", stream="prompt", line="$ " + " ".join(argv))
        text, code = _stream_command(job, argv)
        job.exit_code = code
        parsed = extract_last_json(text)
        if parsed and parsed.get("uuid"):
            job.scan_uuid = str(parsed["uuid"])
            job.emit("scan", scan=parsed, scan_uuid=job.scan_uuid)
        elif code not in (0, 1):
            raise RuntimeError(f"model-security exited {code} without a scan payload")

        if not job.scan_uuid:
            tail = text[-2000:]
            raise RuntimeError(f"could not parse scan UUID from CLI output\n{tail}")

        job.emit("stage", stage="enrich")
        job.emit(
            "log",
            stream="prompt",
            line="$ model-security get-scan-evaluations --scan-uuid " + job.scan_uuid,
        )
        payload = fetch_scan_evaluations(job.scan_uuid)
        payload["duration_ms"] = int((time.monotonic() - job.started_at) * 1000)
        payload["file_count"] = job.file_count
        payload["total_bytes"] = job.total_bytes
        n = len(payload.get("evaluations") or [])
        job.emit("log", stream="meta", line=f"{n} rule evaluations")
        job.emit("detail", **payload)
        job.emit("stage", stage="complete")
