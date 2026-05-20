"""HTS-ASPM push wrapper.

Thin layer on top of :mod:`aibom.aspm_push` that ships the richer
``application/vnd.aibom+json`` envelope built by
:func:`aibom.hts_aspm.payload.build_aspm_payload` (as opposed to the
generic CycloneDX content-type ``aspm_push.push_to_aspm`` ships).

We reuse the underlying ``_do_post`` transport (urllib + injected
``requester`` test seam) so behavior, retries, and error surface
(:class:`aibom.aspm_push.PushError`) match the existing transport.
"""

from __future__ import annotations

import os
from typing import Any

from aibom.aspm_push import PushResponse, Requester, _do_post
from aibom.hts_aspm.payload import (
    ASPM_CONTENT_TYPE,
    SCHEMA_VERSION,
    canonical_json_bytes,
)


def push_aspm_payload(
    url: str,
    payload: dict[str, Any],
    *,
    token_env: str = "ASPM_TOKEN",
    project: str | None = None,
    requester: Requester | None = None,
    extra_headers: dict[str, str] | None = None,
) -> PushResponse:
    """POST the AiBOM ASPM payload to an HTS-ASPM ingest endpoint.

    Headers:

    * ``Content-Type: application/vnd.aibom+json``
    * ``Authorization: Bearer <token from env[token_env]>`` (when set)
    * ``X-Aibom-Schema-Version: 1.0``
    * ``X-Aibom-Scan-Id: <urn:uuid from payload>``
    * ``X-Aibom-Project: <project>`` (when provided)

    The body is the *canonical* JSON encoding of ``payload`` (sorted
    keys, ASCII, no whitespace) — the same payload always yields the
    same bytes on the wire, which makes the scan_id usable as an
    idempotency key on the receiver side.

    Returns the existing :class:`PushResponse` dataclass.
    Raises :class:`aibom.aspm_push.PushError` on 4xx / 5xx.
    """
    token = os.environ.get(token_env)
    headers: dict[str, str] = {
        "Content-Type": ASPM_CONTENT_TYPE,
        "User-Agent": "aibom-hts-aspm-push",
        "X-Aibom-Schema-Version": SCHEMA_VERSION,
    }
    scan_id = payload.get("scan_id")
    if isinstance(scan_id, str) and scan_id:
        headers["X-Aibom-Scan-Id"] = scan_id
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if project:
        headers["X-Aibom-Project"] = project
    if extra_headers:
        for k, v in extra_headers.items():
            headers[str(k)] = str(v)
    body = canonical_json_bytes(payload)
    return _do_post(url, body, headers, requester)


__all__ = ["push_aspm_payload"]
