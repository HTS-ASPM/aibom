"""HTTP webhook receiver — auto-scan and post a PR/MR comment on
push / pull_request / merge_request events.

Pure stdlib (http.server). Single-threaded by design — webhook
deliverers retry on 5xx, and the receiver is meant to run behind a
reverse proxy in any non-trivial deployment.

Routing:
  GET  /healthz                                -> 200 OK
  POST /webhook/github                         -> handle GitHub events
  POST /webhook/gitlab                         -> handle GitLab events
  POST /webhook/bitbucket-server               -> handle BBS events
  POST /webhook/gitea                          -> handle Gitea events

Each POST handler:
  1. Verifies the provider signature (constant-time HMAC compare).
  2. Parses the event payload to extract repo + base/head refs +
     PR/MR number.
  3. Dispatches to a user-supplied `scan_callback(event)` which is
     expected to run a git-diff scan and (optionally) post a comment.

We deliberately do not perform the scan inline — the receiver is a
router. A producer pattern decouples slow scans from the 10s timeout
most providers enforce on webhook delivery.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable

from aibom.webhook.signatures import (
    verify_gitea_signature,
    verify_github_signature,
    verify_gitlab_token,
)


WebhookCallback = Callable[[dict[str, Any]], None]


@dataclass
class WebhookConfig:
    github_secret: str | None = None
    gitea_secret: str | None = None
    gitlab_token: str | None = None
    callback: WebhookCallback | None = None
    accepted_events: tuple[str, ...] = ("push", "pull_request", "merge_request", "pull_request_target")


@dataclass
class WebhookEvent:
    provider: str
    event_type: str
    repo: str
    base_ref: str | None
    head_ref: str | None
    head_sha: str | None
    pr_number: int | None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "event_type": self.event_type,
            "repo": self.repo,
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "head_sha": self.head_sha,
            "pr_number": self.pr_number,
        }


class WebhookHandler(BaseHTTPRequestHandler):
    config: WebhookConfig = WebhookConfig()  # overwritten by create_server

    # Quiet the default request log — operators get their own access log.
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path == "/healthz":
            self._send(200, b"ok\n", "text/plain")
            return
        self._send(404, b"not found\n", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        path = self.path.rstrip("/")
        try:
            if path == "/webhook/github":
                self._handle_github(body)
            elif path == "/webhook/gitlab":
                self._handle_gitlab(body)
            elif path == "/webhook/bitbucket-server":
                self._handle_bitbucket_server(body)
            elif path == "/webhook/gitea":
                self._handle_gitea(body)
            else:
                self._send(404, b"not found\n", "text/plain")
        except _WebhookError as exc:
            self._send(exc.status, json.dumps({"error": exc.message}).encode("utf-8"), "application/json")

    # ----- provider-specific routes -----
    def _handle_github(self, body: bytes) -> None:
        if self.config.github_secret:
            sig = self.headers.get("X-Hub-Signature-256")
            if not verify_github_signature(self.config.github_secret, body, sig):
                raise _WebhookError(401, "invalid GitHub signature")
        event_type = self.headers.get("X-GitHub-Event", "")
        payload = self._parse_json(body)
        if event_type not in self.config.accepted_events:
            self._send(204, b"", "text/plain")
            return
        event = WebhookEvent(
            provider="github",
            event_type=event_type,
            repo=(payload.get("repository") or {}).get("full_name", ""),
            base_ref=((payload.get("pull_request") or {}).get("base") or {}).get("ref"),
            head_ref=((payload.get("pull_request") or {}).get("head") or {}).get("ref"),
            head_sha=((payload.get("pull_request") or {}).get("head") or {}).get("sha")
                     or payload.get("after"),
            pr_number=(payload.get("pull_request") or {}).get("number") or payload.get("number"),
            raw=payload,
        )
        self._dispatch(event)

    def _handle_gitea(self, body: bytes) -> None:
        if self.config.gitea_secret:
            sig = self.headers.get("X-Gitea-Signature")
            if not verify_gitea_signature(self.config.gitea_secret, body, sig):
                raise _WebhookError(401, "invalid Gitea signature")
        event_type = self.headers.get("X-Gitea-Event", "")
        payload = self._parse_json(body)
        if event_type not in self.config.accepted_events:
            self._send(204, b"", "text/plain")
            return
        event = WebhookEvent(
            provider="gitea",
            event_type=event_type,
            repo=(payload.get("repository") or {}).get("full_name", ""),
            base_ref=((payload.get("pull_request") or {}).get("base") or {}).get("ref"),
            head_ref=((payload.get("pull_request") or {}).get("head") or {}).get("ref"),
            head_sha=((payload.get("pull_request") or {}).get("head") or {}).get("sha")
                     or payload.get("after"),
            pr_number=(payload.get("pull_request") or {}).get("number") or payload.get("number"),
            raw=payload,
        )
        self._dispatch(event)

    def _handle_gitlab(self, body: bytes) -> None:
        if self.config.gitlab_token:
            tok = self.headers.get("X-Gitlab-Token")
            if not verify_gitlab_token(self.config.gitlab_token, tok):
                raise _WebhookError(401, "invalid GitLab token")
        event_type = self.headers.get("X-Gitlab-Event", "")
        payload = self._parse_json(body)
        # GitLab uses 'Merge Request Hook' / 'Push Hook' strings — normalize.
        normalized = event_type.lower().replace(" hook", "").replace(" ", "_")
        if normalized not in self.config.accepted_events:
            self._send(204, b"", "text/plain")
            return
        mr = payload.get("object_attributes") or {}
        project = payload.get("project") or {}
        event = WebhookEvent(
            provider="gitlab",
            event_type=normalized,
            repo=str(project.get("id", "")),
            base_ref=mr.get("target_branch"),
            head_ref=mr.get("source_branch"),
            head_sha=mr.get("last_commit", {}).get("id") if isinstance(mr.get("last_commit"), dict) else None,
            pr_number=mr.get("iid"),
            raw=payload,
        )
        self._dispatch(event)

    def _handle_bitbucket_server(self, body: bytes) -> None:
        # No native signature header; we trust upstream proxy / IP allowlist.
        payload = self._parse_json(body)
        event_type = self.headers.get("X-Event-Key", "")
        if event_type.startswith("pr:"):
            normalized = "pull_request"
        elif event_type.startswith("repo:refs_changed"):
            normalized = "push"
        else:
            self._send(204, b"", "text/plain")
            return
        pr = payload.get("pullRequest") or {}
        repo_info = (pr.get("toRef") or {}).get("repository") or (payload.get("repository") or {})
        event = WebhookEvent(
            provider="bitbucket-server",
            event_type=normalized,
            repo=f"{(repo_info.get('project') or {}).get('key', '')}/{repo_info.get('slug', '')}",
            base_ref=(pr.get("toRef") or {}).get("displayId"),
            head_ref=(pr.get("fromRef") or {}).get("displayId"),
            head_sha=(pr.get("fromRef") or {}).get("latestCommit"),
            pr_number=pr.get("id"),
            raw=payload,
        )
        self._dispatch(event)

    # ----- helpers -----
    def _parse_json(self, body: bytes) -> dict[str, Any]:
        if not body:
            raise _WebhookError(400, "empty body")
        try:
            decoded = body.decode("utf-8")
            return json.loads(decoded) if decoded else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _WebhookError(400, f"invalid JSON body: {exc}") from exc

    def _dispatch(self, event: WebhookEvent) -> None:
        if self.config.callback is not None:
            try:
                self.config.callback({"event": event.to_dict(), "raw": event.raw})
            except Exception as exc:  # noqa: BLE001 — never let a callback failure 500 the webhook
                self._send(500, json.dumps({"error": str(exc)}).encode("utf-8"), "application/json")
                return
        self._send(202, json.dumps({"accepted": True, "event": event.to_dict()}).encode("utf-8"), "application/json")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


class _WebhookError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def create_server(config: WebhookConfig, *, host: str = "0.0.0.0", port: int = 8080) -> HTTPServer:
    """Create (but don't start) an HTTPServer wired with the given config."""
    # We use a subclass so each server instance has its own config baked in;
    # http.server expects a handler class, not an instance.
    handler_class = type(
        "BoundWebhookHandler",
        (WebhookHandler,),
        {"config": config},
    )
    return HTTPServer((host, port), handler_class)
