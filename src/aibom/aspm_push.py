"""Push the CycloneDX BOM to an HTS-ASPM endpoint.

Two transports — they share the same payload (CDX 1.6 JSON):

  push_to_aspm(url, token, bom)        POST <url>
  push_to_dependency_track(url, key, bom, project_id)
                                       POST <url>/api/v1/bom

Both functions take an injected `requester` for tests; default uses
urllib so we stay dep-free. Auth is read from an env var name (never
the value, never logged). 4xx / 5xx raises PushError so the CLI can
surface a non-zero exit.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


class PushError(RuntimeError):
    """Raised when an ASPM / Dependency-Track push fails."""


@dataclass
class PushResponse:
    status: int
    body: str


Requester = Callable[[str, bytes, dict[str, str]], PushResponse]


def push_to_aspm(
    url: str,
    bom: dict[str, Any],
    *,
    token_env: str = "ASPM_TOKEN",
    project: str | None = None,
    requester: Requester | None = None,
) -> PushResponse:
    """POST a CDX BOM to an HTS-ASPM ingest endpoint.

    Token is read from os.environ[token_env]. The endpoint URL is the
    fully-qualified ingest URL (we do not do any path mangling — that's
    HTS-ASPM's deployment concern).
    """
    token = os.environ.get(token_env)
    headers = {"Content-Type": "application/vnd.cyclonedx+json", "User-Agent": "aibom-aspm-push"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if project:
        headers["X-Aibom-Project"] = project
    payload = json.dumps(bom).encode("utf-8")
    return _do_post(url, payload, headers, requester)


def push_to_dependency_track(
    base_url: str,
    bom: dict[str, Any],
    project_id: str,
    *,
    api_key_env: str = "DEPENDENCY_TRACK_API_KEY",
    requester: Requester | None = None,
) -> PushResponse:
    """POST a CDX BOM to a Dependency-Track instance at <base>/api/v1/bom."""
    api_key = os.environ.get(api_key_env)
    if not api_key:
        raise PushError(f"missing API key in env {api_key_env}")
    bom_b64 = base64.b64encode(json.dumps(bom).encode("utf-8")).decode("ascii")
    body = json.dumps({"project": project_id, "bom": bom_b64}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
        "User-Agent": "aibom-dt-push",
    }
    url = base_url.rstrip("/") + "/api/v1/bom"
    return _do_post(url, body, headers, requester)


def _do_post(url: str, body: bytes, headers: dict[str, str], requester: Requester | None) -> PushResponse:
    if requester is not None:
        response = requester(url, body, headers)
        if response.status >= 400:
            raise PushError(f"push to {url} failed: {response.status} {response.body[:200]}")
        return response
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:  # noqa: S310
            return PushResponse(status=resp.status, body=resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        raise PushError(f"push to {url} failed: {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise PushError(f"push to {url} failed: {exc.reason}") from exc
