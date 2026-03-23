#!/usr/bin/env python3
"""Print tenant PyPI index URL from SCM (stdout only). Loads config/model-security.env if present."""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        print("Install python-dotenv (project venv: pip install -e .)", file=sys.stderr)
        raise SystemExit(1) from None

    root = _repo_root()
    for name in ("config/model-security.env", ".env", "model-security.env"):
        p = root / name
        if p.is_file():
            load_dotenv(p, override=True)
            return


def main() -> int:
    _load_dotenv()
    client_id = os.environ.get("MODEL_SECURITY_CLIENT_ID", "").strip()
    client_secret = os.environ.get("MODEL_SECURITY_CLIENT_SECRET", "").strip()
    tsg = os.environ.get("TSG_ID", "").strip()
    api = os.environ.get(
        "MODEL_SECURITY_API_ENDPOINT", "https://api.sase.paloaltonetworks.com/aims"
    ).rstrip("/")
    token_ep = os.environ.get(
        "MODEL_SECURITY_TOKEN_ENDPOINT",
        "https://auth.apps.paloaltonetworks.com/oauth2/access_token",
    ).strip()

    if not all((client_id, client_secret, tsg)):
        print(
            "Missing MODEL_SECURITY_CLIENT_ID, MODEL_SECURITY_CLIENT_SECRET, or TSG_ID",
            file=sys.stderr,
        )
        return 1

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    body = f"grant_type=client_credentials&scope=tsg_id:{tsg}".encode()
    tok_req = urllib.request.Request(
        token_ep,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic}",
        },
    )
    try:
        with urllib.request.urlopen(tok_req, timeout=60) as resp:
            tok = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"OAuth token request failed: HTTP {e.code}", file=sys.stderr)
        return 1

    access = tok.get("access_token")
    if not access:
        print("OAuth response had no access_token", file=sys.stderr)
        return 1

    pypi_req = urllib.request.Request(
        f"{api}/mgmt/v1/pypi/authenticate",
        method="GET",
        headers={"Authorization": f"Bearer {access}"},
    )
    try:
        with urllib.request.urlopen(pypi_req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"pypi/authenticate failed: HTTP {e.code}", file=sys.stderr)
        return 1

    url = (data.get("url") or "").strip()
    if not url:
        print("pypi/authenticate response had no url", file=sys.stderr)
        return 1
    print(url, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
