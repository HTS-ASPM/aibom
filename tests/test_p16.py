"""Tests for P16 — `aibom serve` dashboard server, CISA KEV auto-refresh,
and OTel-GenAI runtime reconciliation."""

from __future__ import annotations

import io
import json
import socket
import sys
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.cli import main
from aibom.runtime import reconcile_runtime_with_bom
from aibom.serve import ServeConfig, create_server
from aibom.vex.kev import (
    DEFAULT_KEV_CACHE_PATH,
    KevRefreshError,
    load_kev_feed,
    refresh_kev_feed,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _scan_root(tmp: str) -> Path:
    """Tiny target with at least one detectable signal so the dashboard renders."""
    root = Path(tmp)
    _write(root / "app.py", "from openai import OpenAI\nclient = OpenAI()\n")
    return root


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run_server(config: ServeConfig, fn):
    port = _free_port()
    server = create_server(config, host="127.0.0.1", port=port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        return fn(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _http_get(url: str):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("Content-Type", "")


# --------------------------------------------------------------------------- #
# aibom serve — dashboard server
# --------------------------------------------------------------------------- #

class ServeRoutesTests(unittest.TestCase):
    def test_healthz_returns_ok(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            config = ServeConfig(allowed_root=root)
            status, body, _ = _run_server(
                config, lambda port: _http_get(f"http://127.0.0.1:{port}/healthz"),
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, b"ok\n")

    def test_index_lists_routes(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            config = ServeConfig(allowed_root=root)
            status, body, ctype = _run_server(
                config, lambda port: _http_get(f"http://127.0.0.1:{port}/"),
            )
            self.assertEqual(status, 200)
            self.assertIn("text/html", ctype)
            text = body.decode()
            self.assertIn("/dashboard", text)
            self.assertIn("/asset-graph.json", text)
            self.assertIn("/bom.cdx.json", text)
            self.assertIn("/report/annex-iv", text)

    def test_dashboard_renders_html(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            config = ServeConfig(allowed_root=root)
            status, body, ctype = _run_server(
                config,
                lambda port: _http_get(f"http://127.0.0.1:{port}/dashboard?target={root}"),
            )
            self.assertEqual(status, 200)
            self.assertIn("text/html", ctype)
            text = body.decode()
            for label in ("Findings", "Files scanned", "AI assets"):
                self.assertIn(label, text)

    def test_asset_graph_json_parses(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            config = ServeConfig(allowed_root=root)
            status, body, ctype = _run_server(
                config,
                lambda port: _http_get(
                    f"http://127.0.0.1:{port}/asset-graph.json?target={root}"
                ),
            )
            self.assertEqual(status, 200)
            self.assertIn("application/json", ctype)
            payload = json.loads(body)
            self.assertIn("nodes", payload)
            self.assertIn("edges", payload)

    def test_scan_json_returns_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            config = ServeConfig(allowed_root=root)
            status, body, _ = _run_server(
                config,
                lambda port: _http_get(f"http://127.0.0.1:{port}/scan.json?target={root}"),
            )
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertIn("findings", payload)

    def test_bom_route_returns_cyclonedx(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            config = ServeConfig(allowed_root=root)
            status, body, _ = _run_server(
                config,
                lambda port: _http_get(f"http://127.0.0.1:{port}/bom.cdx.json?target={root}"),
            )
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertEqual(payload.get("bomFormat"), "CycloneDX")
            self.assertEqual(payload.get("specVersion"), "1.6")

    def test_report_route(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            config = ServeConfig(allowed_root=root)
            status, body, ctype = _run_server(
                config,
                lambda port: _http_get(
                    f"http://127.0.0.1:{port}/report/annex-iv?target={root}"
                ),
            )
            self.assertEqual(status, 200)
            self.assertIn("text/html", ctype)
            self.assertIn("Annex IV", body.decode())

    def test_unknown_report_type_404(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            config = ServeConfig(allowed_root=root)
            status, _, _ = _run_server(
                config,
                lambda port: _http_get(
                    f"http://127.0.0.1:{port}/report/bogus?target={root}"
                ),
            )
            self.assertEqual(status, 404)

    def test_path_traversal_rejected(self) -> None:
        with TemporaryDirectory() as outer:
            allowed = Path(outer) / "allowed"
            allowed.mkdir()
            _write(allowed / "app.py", "from openai import OpenAI\n")
            # Make an unrelated directory and try to scan it via ../
            evil = Path(outer) / "secret"
            evil.mkdir()
            _write(evil / "x.txt", "nothing")
            config = ServeConfig(allowed_root=allowed.resolve())
            status, body, ctype = _run_server(
                config,
                lambda port: _http_get(
                    f"http://127.0.0.1:{port}/dashboard?target={evil}"
                ),
            )
            self.assertEqual(status, 400)
            self.assertIn("application/json", ctype)
            payload = json.loads(body)
            self.assertIn("outside allowed root", payload.get("error", ""))


# --------------------------------------------------------------------------- #
# aibom serve — CLI smoke
# --------------------------------------------------------------------------- #

class ServeCliSmokeTests(unittest.TestCase):
    def test_serve_help(self) -> None:
        buf = io.StringIO()
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(buf):
                main(["serve", "--help"])
        self.assertEqual(cm.exception.code, 0)
        text = buf.getvalue()
        self.assertIn("--host", text)
        self.assertIn("--allowed-root", text)


# --------------------------------------------------------------------------- #
# CISA KEV auto-refresh
# --------------------------------------------------------------------------- #

_FAKE_KEV_PAYLOAD = {
    "title": "Catalog",
    "catalogVersion": "2026.05.20",
    "dateReleased": "2026-05-20",
    "vulnerabilities": [
        {
            "cveID": "CVE-2025-0001",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget RCE",
            "dateAdded": "2025-12-01",
            "shortDescription": "Remote code exec via widget endpoint.",
            "requiredAction": "Apply update",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2025-0002",
            "vendorProject": "Beta",
            "product": "Gizmo",
            "vulnerabilityName": "Beta Gizmo path traversal",
            "dateAdded": "2025-12-02",
            "shortDescription": "Path traversal in gizmo.",
            "requiredAction": "Apply update",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


class KevRefreshTests(unittest.TestCase):
    def test_refresh_writes_destination_atomically(self) -> None:
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "kev.json"
            calls: list[str] = []

            def fetcher(url: str) -> bytes:
                calls.append(url)
                return json.dumps(_FAKE_KEV_PAYLOAD).encode("utf-8")

            summary = refresh_kev_feed(
                dest, source_url="https://example/feed.json", fetcher=fetcher,
            )
            self.assertEqual(summary["vulnerabilities"], 2)
            self.assertEqual(summary["catalog_version"], "2026.05.20")
            self.assertEqual(summary["destination"], str(dest))
            self.assertEqual(calls, ["https://example/feed.json"])
            # Loading the freshly written file should round-trip.
            loaded = load_kev_feed(dest)
            self.assertIn("CVE-2025-0001", loaded)
            self.assertTrue(loaded["CVE-2025-0001"].known_ransomware)
            self.assertFalse(loaded["CVE-2025-0002"].known_ransomware)
            # No leftover tmp.
            self.assertFalse(dest.with_suffix(dest.suffix + ".tmp").exists())

    def test_refresh_fetcher_error_leaves_destination_untouched(self) -> None:
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "kev.json"
            # Pre-seed the destination with a known marker.
            dest.write_text(json.dumps({"sentinel": True}), encoding="utf-8")

            def boom(url: str) -> bytes:
                raise KevRefreshError("network down")

            with self.assertRaises(KevRefreshError):
                refresh_kev_feed(dest, source_url="https://example/", fetcher=boom)

            # File untouched, no tmp left.
            self.assertEqual(json.loads(dest.read_text())["sentinel"], True)
            self.assertFalse(dest.with_suffix(dest.suffix + ".tmp").exists())

    def test_refresh_rejects_non_dict_payload(self) -> None:
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "kev.json"
            def fetcher(url: str) -> bytes:
                return b"[]"
            with self.assertRaises(KevRefreshError):
                refresh_kev_feed(dest, fetcher=fetcher)


class KevRefreshCliTests(unittest.TestCase):
    def test_cli_uses_file_url_for_air_gapped(self) -> None:
        with TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.json"
            fixture.write_text(json.dumps(_FAKE_KEV_PAYLOAD), encoding="utf-8")
            dest = Path(tmp) / "out.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([
                    "kev-refresh",
                    "--destination", str(dest),
                    "--source-url", f"file://{fixture}",
                ])
            self.assertEqual(rc, 0)
            self.assertTrue(dest.exists())
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary["vulnerabilities"], 2)

    def test_cli_no_network_without_source_url_errors(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main(["kev-refresh", "--no-network"])
        self.assertEqual(rc, 3)
        self.assertIn("--no-network", buf.getvalue())


# --------------------------------------------------------------------------- #
# OTel-GenAI reconciliation
# --------------------------------------------------------------------------- #

def _span(system: str, model: str, in_tokens: int = 10, out_tokens: int = 20, service: str = "svc") -> dict:
    return {
        "attributes": {
            "gen_ai.system": system,
            "gen_ai.response.model": model,
            "gen_ai.usage.input_tokens": in_tokens,
            "gen_ai.usage.output_tokens": out_tokens,
        },
        "resource": {"attributes": {"service.name": service}},
    }


def _bom_with_models(*model_names: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "machine-learning-model",
                "bom-ref": f"model:{name}",
                "name": name,
            }
            for name in model_names
        ],
    }


class ReconcileTests(unittest.TestCase):
    def test_basic_match(self) -> None:
        bom = _bom_with_models("openai/gpt-4o")
        spans = [_span("openai", "gpt-4o"), _span("openai", "gpt-4o", 5, 5)]
        report = reconcile_runtime_with_bom(bom, spans)
        self.assertEqual(report["summary"]["match_count"], 1)
        self.assertEqual(report["summary"]["shadow_model_count"], 0)
        self.assertEqual(report["summary"]["dead_inventory_count"], 0)
        self.assertEqual(report["summary"]["total_observed_invocations"], 2)
        observed = report["observed_models"][0]
        self.assertEqual(observed["invocation_count"], 2)
        self.assertEqual(observed["total_input_tokens"], 15)
        self.assertEqual(observed["total_output_tokens"], 25)

    def test_shadow_ai_detected(self) -> None:
        bom = _bom_with_models("openai/gpt-4o")
        spans = [_span("anthropic", "claude-3-5-sonnet")]
        report = reconcile_runtime_with_bom(bom, spans)
        self.assertEqual(report["summary"]["shadow_model_count"], 1)
        self.assertEqual(report["in_runtime_not_in_bom"][0]["model"], "claude-3-5-sonnet")
        # And the bom's gpt-4o is dead inventory.
        self.assertEqual(report["summary"]["dead_inventory_count"], 1)

    def test_dead_inventory_detected(self) -> None:
        bom = _bom_with_models("openai/gpt-4o", "legacy/davinci")
        spans = [_span("openai", "gpt-4o-2024-08-06")]
        report = reconcile_runtime_with_bom(bom, spans)
        # Family-prefix match handles the dated variant.
        self.assertEqual(report["summary"]["match_count"], 1)
        dead = report["in_bom_not_in_runtime"]
        self.assertEqual(len(dead), 1)
        self.assertEqual(dead[0]["name"], "legacy/davinci")

    def test_load_otel_spans_handles_otlp_envelope(self) -> None:
        from aibom.runtime import load_otel_spans
        with TemporaryDirectory() as tmp:
            payload = {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "svc"}},
                            ],
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "attributes": [
                                            {"key": "gen_ai.system", "value": {"stringValue": "openai"}},
                                            {"key": "gen_ai.response.model", "value": {"stringValue": "gpt-4o"}},
                                            {"key": "gen_ai.usage.input_tokens", "value": {"intValue": 7}},
                                            {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 9}},
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            }
            p = Path(tmp) / "spans.json"
            p.write_text(json.dumps(payload), encoding="utf-8")
            spans = load_otel_spans(p)
            self.assertEqual(len(spans), 1)
            attrs = spans[0]["attributes"]
            self.assertEqual(attrs["gen_ai.system"], "openai")
            self.assertEqual(attrs["gen_ai.usage.input_tokens"], 7)


class ReconcileCliTests(unittest.TestCase):
    def test_cli_writes_report(self) -> None:
        with TemporaryDirectory() as tmp:
            bom_path = Path(tmp) / "bom.json"
            traces_path = Path(tmp) / "spans.json"
            out_path = Path(tmp) / "report.json"
            bom_path.write_text(json.dumps(_bom_with_models("openai/gpt-4o")), encoding="utf-8")
            traces_path.write_text(
                json.dumps([_span("openai", "gpt-4o")]),
                encoding="utf-8",
            )
            buf_err = io.StringIO()
            with redirect_stderr(buf_err):
                rc = main([
                    "reconcile",
                    str(bom_path), str(traces_path),
                    "--output", str(out_path),
                ])
            self.assertEqual(rc, 0)
            report = json.loads(out_path.read_text())
            self.assertEqual(report["summary"]["match_count"], 1)
            self.assertIn("matches", buf_err.getvalue())


if __name__ == "__main__":
    unittest.main()
