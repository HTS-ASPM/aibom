"""Tests for the HTS-ASPM integration glue (payload + push + CLI)."""

from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from aibom.aspm_push import PushError, PushResponse
from aibom.cli import main
from aibom.hts_aspm import (
    ASPM_CONTENT_TYPE,
    SCHEMA_VERSION,
    build_aspm_payload,
    canonical_json_bytes,
    push_aspm_payload,
)
from aibom.models import Finding, MatchEvidence, ScanResult, ScanStats


def _make_finding(
    *,
    finding_id: str = "prov:openai:src/llm.py:12",
    rule_id: str = "provider.openai.pattern",
    category: str = "provider",
    name: str = "openai",
    severity: str = "high",
    confidence: str = "high",
    path: str = "src/llm.py",
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        category=category,
        name=name,
        severity=severity,
        confidence=confidence,
        path=path,
        detector="regex",
        entity_type="component",
        source_kind="code",
        summary=f"matched {name}",
        evidence=[MatchEvidence(line=12, snippet="...openai...", match="openai")],
        metadata=metadata or {
            "owasp_llm": ["LLM05-supply-chain"],
            "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
            "nist_ai_rmf": ["GV-1.3"],
        },
    )


def _make_result() -> ScanResult:
    findings = [
        _make_finding(),
        _make_finding(
            finding_id="prompt:jb:src/router.py:42",
            rule_id="prompt_risk.jailbreak",
            category="prompt_risk",
            name="jailbreak phrasing",
            severity="critical",
            path="src/router.py",
            metadata={
                "owasp_llm": ["LLM01-prompt-injection"],
                "nist_ai_rmf": ["MS-2.10"],
            },
        ),
        _make_finding(
            finding_id="model:gpt:src/llm.py:20",
            rule_id="model.pattern",
            category="model",
            name="gpt-4",
            severity="medium",
            confidence="medium",
            metadata={"owasp_llm": ["LLM05-supply-chain"]},
        ),
        _make_finding(
            finding_id="prov:anth:src/llm.py:30",
            rule_id="provider.anthropic.pattern",
            category="provider",
            name="anthropic",
            severity="low",
            metadata={"owasp_llm": ["LLM05-supply-chain"]},
        ),
    ]
    return ScanResult(
        root="/repo/acme/llm-app",
        findings=findings,
        stats=ScanStats(files_scanned=10, files_skipped=0, bytes_scanned=12345),
    )


_FIXED_NOW = datetime(2026, 5, 20, 11, 22, 33, tzinfo=timezone.utc)


class BuildPayloadTests(unittest.TestCase):
    def test_populates_all_required_keys(self) -> None:
        payload = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        required = {
            "schema_version", "scanner", "scan_root", "scan_id", "scanned_at",
            "bom", "asset_graph", "findings_summary", "top_findings",
            "risk_scores", "vex", "kev_matches",
        }
        self.assertTrue(required.issubset(payload.keys()), f"missing keys: {required - payload.keys()}")
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertEqual(payload["scanner"]["name"], "aibom")
        self.assertEqual(payload["scan_root"], "/repo/acme/llm-app")
        self.assertEqual(payload["scanned_at"], "2026-05-20T11:22:33Z")
        self.assertTrue(payload["scan_id"].startswith("urn:uuid:"))
        # bom is a CDX 1.6 document
        self.assertEqual(payload["bom"]["bomFormat"], "CycloneDX")
        self.assertEqual(payload["bom"]["specVersion"], "1.6")
        # asset_graph has nodes + edges
        self.assertIn("nodes", payload["asset_graph"])
        self.assertIn("edges", payload["asset_graph"])

    def test_signature_manifest_only_when_signer_provided(self) -> None:
        payload = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        self.assertNotIn("signature_manifest", payload)
        payload_signed = build_aspm_payload(
            _make_result(),
            include_kev=False,
            now=_FIXED_NOW,
            signer="ci@hts.consulting",
            key_ref="env://COSIGN_KEY",
        )
        self.assertIn("signature_manifest", payload_signed)
        manifest = payload_signed["signature_manifest"]
        self.assertEqual(manifest["intended_signer"], "ci@hts.consulting")
        self.assertEqual(len(manifest["sha256"]), 64)  # sha256 hex

    def test_findings_summary_counts_match_raw_findings(self) -> None:
        result = _make_result()
        payload = build_aspm_payload(result, include_kev=False, now=_FIXED_NOW)
        summary = payload["findings_summary"]

        # by_severity
        expected_severity: dict[str, int] = {sev: 0 for sev in ("info", "low", "medium", "high", "critical")}
        for f in result.findings:
            expected_severity[f.severity] += 1
        self.assertEqual(summary["by_severity"], expected_severity)

        # by_category
        expected_category: dict[str, int] = {}
        for f in result.findings:
            expected_category[f.category] = expected_category.get(f.category, 0) + 1
        self.assertEqual(summary["by_category"], expected_category)

        # by_framework
        expected_owasp: dict[str, int] = {}
        expected_atlas: dict[str, int] = {}
        expected_nist: dict[str, int] = {}
        for f in result.findings:
            for ref in f.metadata.get("owasp_llm", []) or []:
                expected_owasp[ref] = expected_owasp.get(ref, 0) + 1
            for ref in f.metadata.get("mitre_atlas", []) or []:
                expected_atlas[ref] = expected_atlas.get(ref, 0) + 1
            for ref in f.metadata.get("nist_ai_rmf", []) or []:
                expected_nist[ref] = expected_nist.get(ref, 0) + 1
        self.assertEqual(summary["by_framework"]["owasp_llm"], expected_owasp)
        self.assertEqual(summary["by_framework"]["mitre_atlas"], expected_atlas)
        self.assertEqual(summary["by_framework"]["nist_ai_rmf"], expected_nist)

        self.assertEqual(summary["total"], len(result.findings))

    def test_top_findings_sorted_severity_desc(self) -> None:
        payload = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        top = payload["top_findings"]
        # critical comes before high comes before medium comes before low.
        order = ("info", "low", "medium", "high", "critical")
        ranks = [order.index(f["severity"]) for f in top]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_top_findings_capped_at_50(self) -> None:
        many = [
            _make_finding(finding_id=f"f:{i}", severity="medium")
            for i in range(120)
        ]
        result = ScanResult(root="/r", findings=many, stats=ScanStats())
        payload = build_aspm_payload(result, include_kev=False, now=_FIXED_NOW)
        self.assertEqual(len(payload["top_findings"]), 50)

    def test_risk_scores_sorted_desc(self) -> None:
        payload = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        scores = [row["score"] for row in payload["risk_scores"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_determinism_same_bytes_for_same_input(self) -> None:
        # Two builds with the same fixed `now` produce identical canonical bytes.
        result1 = _make_result()
        result2 = _make_result()
        payload1 = build_aspm_payload(result1, include_kev=False, now=_FIXED_NOW)
        payload2 = build_aspm_payload(result2, include_kev=False, now=_FIXED_NOW)
        self.assertEqual(canonical_json_bytes(payload1), canonical_json_bytes(payload2))

    def test_different_timestamps_produce_different_scan_ids(self) -> None:
        p1 = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        p2 = build_aspm_payload(
            _make_result(),
            include_kev=False,
            now=datetime(2026, 5, 20, 11, 22, 34, tzinfo=timezone.utc),
        )
        self.assertNotEqual(p1["scan_id"], p2["scan_id"])

    def test_no_kev_when_disabled(self) -> None:
        payload = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        self.assertEqual(payload["kev_matches"], [])

    def test_no_vex_when_disabled(self) -> None:
        payload = build_aspm_payload(
            _make_result(),
            include_vex=False,
            include_kev=False,
            now=_FIXED_NOW,
        )
        self.assertEqual(payload["vex"], [])


class PushAspmPayloadTests(unittest.TestCase):
    def test_sends_aibom_content_type_and_headers(self) -> None:
        captured: dict = {}

        def requester(url, body, headers):
            captured["url"] = url
            captured["body"] = body
            captured["headers"] = headers
            return PushResponse(status=200, body='{"ingested": true, "asset_count": 3}')

        payload = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        with mock.patch.dict(os.environ, {"ASPM_TOKEN": "tok-xyz"}):
            response = push_aspm_payload(
                "https://aspm.example.com/aibom/ingest",
                payload,
                project="acme/llm-app",
                requester=requester,
            )

        self.assertEqual(response.status, 200)
        self.assertEqual(captured["url"], "https://aspm.example.com/aibom/ingest")
        self.assertEqual(captured["headers"]["Content-Type"], ASPM_CONTENT_TYPE)
        self.assertEqual(captured["headers"]["X-Aibom-Schema-Version"], SCHEMA_VERSION)
        self.assertEqual(captured["headers"]["X-Aibom-Scan-Id"], payload["scan_id"])
        self.assertEqual(captured["headers"]["X-Aibom-Project"], "acme/llm-app")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer tok-xyz")
        # Body is canonical bytes.
        self.assertEqual(captured["body"], canonical_json_bytes(payload))

    def test_no_token_omits_authorization(self) -> None:
        captured: dict = {}

        def requester(url, body, headers):
            captured["headers"] = headers
            return PushResponse(status=200, body="")

        payload = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        with mock.patch.dict(os.environ, {}, clear=True):
            push_aspm_payload("https://aspm.example", payload, requester=requester)
        self.assertNotIn("Authorization", captured["headers"])

    def test_4xx_raises_push_error(self) -> None:
        def requester(url, body, headers):
            return PushResponse(status=413, body="too big")

        payload = build_aspm_payload(_make_result(), include_kev=False, now=_FIXED_NOW)
        with self.assertRaises(PushError):
            push_aspm_payload("https://aspm.example", payload, requester=requester)


class PushCliTests(unittest.TestCase):
    def test_push_command_end_to_end(self) -> None:
        captured: dict = {}

        def fake_requester(url, body, headers):
            captured["url"] = url
            captured["body"] = body
            captured["headers"] = headers
            return PushResponse(status=200, body='{"ingested": true, "asset_count": 1}')

        fixture = Path(__file__).parent / "fixtures" / "python_app"
        with mock.patch("aibom.cli._PUSH_REQUESTER", fake_requester):
            with mock.patch.dict(os.environ, {"ASPM_TOKEN": "cli-token"}, clear=False):
                with mock.patch("sys.stdout", new_callable=StringIO) as stdout:
                    exit_code = main([
                        "push", str(fixture),
                        "--aspm-url", "https://aspm.example.com/ingest",
                        "--project", "acme/test",
                        "--no-kev",
                    ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["url"], "https://aspm.example.com/ingest")
        self.assertEqual(captured["headers"]["Content-Type"], ASPM_CONTENT_TYPE)
        self.assertEqual(captured["headers"]["X-Aibom-Project"], "acme/test")
        self.assertEqual(captured["headers"]["X-Aibom-Schema-Version"], SCHEMA_VERSION)
        self.assertIn("X-Aibom-Scan-Id", captured["headers"])

        summary = json.loads(stdout.getvalue())
        self.assertTrue(summary["posted"])
        self.assertEqual(summary["status"], 200)
        self.assertEqual(summary["schema_version"], SCHEMA_VERSION)
        self.assertTrue(summary["scan_id"].startswith("urn:uuid:"))
        self.assertIsInstance(summary["findings_total"], int)

        # body sent on the wire is the canonical encoding of the payload built
        # by the CLI; decode and verify the contract shape.
        body = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(body["schema_version"], SCHEMA_VERSION)
        self.assertEqual(body["bom"]["bomFormat"], "CycloneDX")
        self.assertIn("findings_summary", body)

    def test_push_command_missing_target_returns_2(self) -> None:
        with mock.patch("sys.stdout", new_callable=StringIO), \
                mock.patch("sys.stderr", new_callable=StringIO):
            exit_code = main([
                "push", "/nonexistent/path/should-not-exist-9f8e7d",
                "--aspm-url", "https://aspm.example.com/ingest",
            ])
        self.assertEqual(exit_code, 2)

    def test_push_command_push_failure_returns_4(self) -> None:
        def failing_requester(url, body, headers):
            return PushResponse(status=500, body="boom")

        fixture = Path(__file__).parent / "fixtures" / "python_app"
        with mock.patch("aibom.cli._PUSH_REQUESTER", failing_requester):
            with mock.patch("sys.stdout", new_callable=StringIO), \
                    mock.patch("sys.stderr", new_callable=StringIO):
                exit_code = main([
                    "push", str(fixture),
                    "--aspm-url", "https://aspm.example.com/ingest",
                    "--no-kev",
                ])
        self.assertEqual(exit_code, 4)


if __name__ == "__main__":
    unittest.main()
