"""Pure-stdlib HTTP dashboard server.

The web dashboard the SaaS competitors (Cycode, Mend, Endor) put
behind their landing page — but as a single ThreadingHTTPServer that
runs anywhere Python runs. No FastAPI, no Flask, no Starlette: just
``http.server.ThreadingHTTPServer`` + ``BaseHTTPRequestHandler``.

Routes:
  GET /                                 → HTML index
  GET /healthz                          → "ok"
  GET /dashboard?target=<path>          → executive dashboard HTML
  GET /asset-graph.json?target=<path>   → asset-graph JSON
  GET /scan.json?target=<path>          → raw scan JSON
  GET /bom.cdx.json?target=<path>       → CycloneDX 1.6 BOM JSON
  GET /report/{type}?target=<path>      → compliance report HTML
                                          (type ∈ annex-iv|nist-rmf|iso-42001)

Path-traversal protection: ``target`` is resolved and rejected unless
it lives under the configured ``allowed_root`` (default cwd).
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from aibom.asset_graph import render_asset_graph_json
from aibom.compliance import (
    generate_annex_iv_html,
    generate_iso_42001_html,
    generate_nist_rmf_html,
)
from aibom.cyclonedx import build_bom
from aibom.dashboard import generate_executive_dashboard_html
from aibom.reporters import render_json
from aibom.scanner import scan_path


_REPORT_GENERATORS = {
    "annex-iv": generate_annex_iv_html,
    "nist-rmf": generate_nist_rmf_html,
    "iso-42001": generate_iso_42001_html,
}


@dataclass(frozen=True, slots=True)
class ServeConfig:
    """Server configuration baked into the request handler subclass."""

    allowed_root: Path

    def _root(self) -> Path:
        return self.allowed_root.expanduser().resolve()

    def resolve_target(self, raw: str | None) -> Path:
        """Resolve ``raw`` (a query-string path) under ``allowed_root``.

        Raises ``_BadRequest`` if the resolved path escapes the allowed
        root — that's our path-traversal guard. Both sides are
        ``resolve()``-d so /tmp <-> /private/tmp symlinks on macOS
        compare correctly.
        """
        root = self._root()
        candidate = (raw or "").strip() or str(root)
        target = Path(candidate).expanduser()
        if not target.is_absolute():
            target = root / target
        target = target.resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise _BadRequest(
                f"target {target} is outside allowed root {root}"
            ) from exc
        if not target.exists():
            raise _BadRequest(f"target does not exist: {target}")
        return target


class _BadRequest(RuntimeError):
    """Raised by handlers to return a 400 with the given message."""


class DashboardHandler(BaseHTTPRequestHandler):
    config: ServeConfig = ServeConfig(allowed_root=Path.cwd().resolve())

    # Match webhook/receiver.py — quiet the default access log so the
    # parent process can run its own structured one.
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:  # noqa: N802 (stdlib API)
        parts = urlsplit(self.path)
        route = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query)
        target_raw = (query.get("target") or [None])[0]

        try:
            if route == "/":
                self._send_html(200, _render_index())
                return
            if route == "/healthz":
                self._send(200, b"ok\n", "text/plain")
                return
            if route == "/dashboard":
                target = self.config.resolve_target(target_raw)
                result = scan_path(target)
                self._send_html(200, generate_executive_dashboard_html(result))
                return
            if route == "/asset-graph.json":
                target = self.config.resolve_target(target_raw)
                result = scan_path(target)
                self._send_json(200, render_asset_graph_json(result))
                return
            if route == "/scan.json":
                target = self.config.resolve_target(target_raw)
                result = scan_path(target)
                self._send_json(200, render_json(result))
                return
            if route == "/bom.cdx.json":
                target = self.config.resolve_target(target_raw)
                result = scan_path(target)
                self._send_json(200, json.dumps(build_bom(result), indent=2))
                return
            if route.startswith("/report/"):
                report_type = route[len("/report/"):]
                generator = _REPORT_GENERATORS.get(report_type)
                if generator is None:
                    self._send(
                        404,
                        f"unknown report type: {report_type}\n".encode("utf-8"),
                        "text/plain",
                    )
                    return
                target = self.config.resolve_target(target_raw)
                result = scan_path(target)
                self._send_html(200, generator(result))
                return
            self._send(404, b"not found\n", "text/plain")
        except _BadRequest as exc:
            self._send(
                400,
                json.dumps({"error": str(exc)}).encode("utf-8"),
                "application/json",
            )
        except Exception as exc:  # noqa: BLE001 — never 500 silently
            self._send(
                500,
                json.dumps({"error": str(exc)}).encode("utf-8"),
                "application/json",
            )

    # ----- send helpers -----
    def _send_html(self, status: int, body: str) -> None:
        self._send(status, body.encode("utf-8"), "text/html; charset=utf-8")

    def _send_json(self, status: int, body: str) -> None:
        self._send(status, body.encode("utf-8"), "application/json")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)


def create_server(
    config: ServeConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8088,
) -> ThreadingHTTPServer:
    """Create (but don't start) a ``ThreadingHTTPServer`` bound to ``config``."""
    handler_class = type(
        "BoundDashboardHandler",
        (DashboardHandler,),
        {"config": config},
    )
    return ThreadingHTTPServer((host, port), handler_class)


def _render_index() -> str:
    """Tiny self-contained HTML index — links every other route."""
    rows = [
        ("/healthz", "Liveness probe (text/plain)"),
        ("/dashboard?target=.", "Executive dashboard for the cwd"),
        ("/asset-graph.json?target=.", "Asset graph JSON"),
        ("/scan.json?target=.", "Raw scan JSON"),
        ("/bom.cdx.json?target=.", "CycloneDX 1.6 BOM"),
        ("/report/annex-iv?target=.", "EU AI Act Annex IV"),
        ("/report/nist-rmf?target=.", "NIST AI RMF crosswalk"),
        ("/report/iso-42001?target=.", "ISO/IEC 42001 crosswalk"),
    ]
    items = "".join(
        f"<li><a href='{html.escape(path)}'><code>{html.escape(path)}</code></a>"
        f" — {html.escape(desc)}</li>"
        for path, desc in rows
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>AiBOM — server index</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2em;max-width:48em}"
        "code{background:#f4f4f4;padding:0.1em 0.3em;border-radius:3px}"
        "h1{font-size:1.3em}li{margin:.4em 0}</style>"
        "</head><body>"
        "<h1>AiBOM dashboard server</h1>"
        "<p>Available routes:</p>"
        f"<ul>{items}</ul>"
        "</body></html>"
    )
