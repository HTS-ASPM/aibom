"""Webhook signature / token verification.

Each provider authenticates webhook deliveries differently:

  GitHub        X-Hub-Signature-256: sha256=<HMAC>
  Gitea         X-Gitea-Signature: <HMAC hex>  (sha256 of the body)
  GitLab        X-Gitlab-Token: <shared secret>  (constant-time compare)
  Bitbucket Server  No signature header — operators rely on IP allowlist
                    or mTLS; we still expose a hook that always returns
                    True so the routing code stays uniform.

All comparisons are constant-time (`hmac.compare_digest`).
"""

from __future__ import annotations

import hashlib
import hmac


def verify_github_signature(secret: str, body: bytes, header_value: str | None) -> bool:
    if not secret or not header_value or not header_value.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_value)


def verify_gitea_signature(secret: str, body: bytes, header_value: str | None) -> bool:
    if not secret or not header_value:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_value)


def verify_gitlab_token(secret: str, header_value: str | None) -> bool:
    if not secret or not header_value:
        return False
    return hmac.compare_digest(secret, header_value)


def verify_bitbucket_server() -> bool:
    """Bitbucket Server has no webhook signature; operators rely on
    IP allowlist / mTLS. Returning True keeps the routing uniform —
    deployers are expected to front the receiver with a reverse proxy
    that enforces source IP."""
    return True
