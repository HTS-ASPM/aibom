"""Shared HTTP POST helper for the PR-comment connectors.

Pure stdlib. Tests inject a `requester` callable instead of touching
the network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable


class PrCommentError(RuntimeError):
    pass


Requester = Callable[[str, bytes, dict[str, str]], dict[str, Any]]


def post_json(
    url: str,
    body: dict[str, Any],
    *,
    headers: dict[str, str],
    requester: Requester | None = None,
) -> dict[str, Any]:
    payload = json.dumps(body).encode("utf-8")
    if requester is not None:
        return requester(url, payload, headers)
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:  # noqa: S310
            text = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "body": text}
    except urllib.error.HTTPError as exc:
        raise PrCommentError(f"POST {url} failed: {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise PrCommentError(f"POST {url} failed: {exc.reason}") from exc
