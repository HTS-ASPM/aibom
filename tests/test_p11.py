"""Tests for P11 — webhook receiver + GitHub Check Run + VS Code scaffold."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
import unittest
import urllib.request
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.models import Finding, MatchEvidence, ScanResult, ScanStats
from aibom.webhook import (
    WebhookConfig,
    build_check_run_body,
    create_server,
    post_check_run,
    verify_gitea_signature,
    verify_github_signature,
    verify_gitlab_token,
)


# --------------------------------------------------------------------------- #
# Signature verification
# --------------------------------------------------------------------------- #

class SignatureTests(unittest.TestCase):
    def test_github_signature_valid(self) -> None:
        body = b'{"hello":"world"}'
        sig = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_github_signature("secret", body, sig))

    def test_github_signature_invalid(self) -> None:
        body = b'{"hello":"world"}'
        self.assertFalse(verify_github_signature("secret", body, "sha256=deadbeef"))
        self.assertFalse(verify_github_signature("secret", body, None))
        self.assertFalse(verify_github_signature("", body, "sha256=anything"))

    def test_gitea_signature(self) -> None:
        body = b'{"hi":1}'
        sig = hmac.new(b"k", body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_gitea_signature("k", body, sig))
        self.assertFalse(verify_gitea_signature("k", body, "wrong"))

    def test_gitlab_token(self) -> None:
        self.assertTrue(verify_gitlab_token("shared", "shared"))
        self.assertFalse(verify_gitlab_token("shared", "different"))
        self.assertFalse(verify_gitlab_token("", "anything"))


# --------------------------------------------------------------------------- #
# Check Run body builder
# --------------------------------------------------------------------------- #

def _f(rule_id: str, severity: str, path: str = "app.py", line: int = 1) -> Finding:
    return Finding(
        finding_id=f"id-{rule_id}",
        rule_id=rule_id, category="provider", name=rule_id,
        severity=severity, confidence="high", path=path,
        detector="d", entity_type="provider", source_kind="source",
        summary=f"{rule_id} summary",
        evidence=[MatchEvidence(line=line, snippet="x", match="x")],
        metadata={},
    )


class CheckRunBodyTests(unittest.TestCase):
    def test_failure_when_critical(self) -> None:
        result = ScanResult(root="/tmp", findings=[_f("a", "critical")], stats=ScanStats())
        body = build_check_run_body(result, head_sha="abc123")
        self.assertEqual(body["status"], "completed")
        self.assertEqual(body["conclusion"], "failure")
        self.assertEqual(body["head_sha"], "abc123")
        self.assertEqual(body["output"]["annotations"][0]["annotation_level"], "failure")

    def test_neutral_when_only_low(self) -> None:
        result = ScanResult(root="/tmp", findings=[_f("a", "low")], stats=ScanStats())
        body = build_check_run_body(result, head_sha="abc123")
        self.assertEqual(body["conclusion"], "neutral")

    def test_success_when_no_findings(self) -> None:
        result = ScanResult(root="/tmp", findings=[], stats=ScanStats())
        body = build_check_run_body(result, head_sha="abc123")
        self.assertEqual(body["conclusion"], "success")

    def test_annotation_cap_at_50(self) -> None:
        findings = [_f(f"rule{i}", "high") for i in range(75)]
        result = ScanResult(root="/tmp", findings=findings, stats=ScanStats())
        body = build_check_run_body(result, head_sha="abc")
        self.assertEqual(len(body["output"]["annotations"]), 50)

    def test_details_url_optional(self) -> None:
        result = ScanResult(root="/tmp", findings=[], stats=ScanStats())
        body_no_url = build_check_run_body(result, head_sha="abc")
        self.assertNotIn("details_url", body_no_url)
        body_with_url = build_check_run_body(result, head_sha="abc", details_url="https://example/x")
        self.assertEqual(body_with_url["details_url"], "https://example/x")


class CheckRunPostTests(unittest.TestCase):
    def test_post_uses_bearer(self) -> None:
        captured: dict = {}
        def requester(url, body, headers):
            captured["url"] = url
            captured["headers"] = headers
            return {"status": 201}
        os.environ["GITHUB_TOKEN"] = "ghp_test"
        try:
            post_check_run("acme/app", {"x": 1}, requester=requester)
            self.assertEqual(captured["url"], "https://api.github.com/repos/acme/app/check-runs")
            self.assertEqual(captured["headers"]["Authorization"], "Bearer ghp_test")
        finally:
            del os.environ["GITHUB_TOKEN"]


# --------------------------------------------------------------------------- #
# Webhook receiver — end-to-end on a random port
# --------------------------------------------------------------------------- #

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class WebhookReceiverTests(unittest.TestCase):
    def _run_with_server(self, config: WebhookConfig, fn):
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

    def test_healthz(self) -> None:
        def go(port):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as resp:
                return resp.status, resp.read()
        status, body = self._run_with_server(WebhookConfig(), go)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok\n")

    def test_github_push_dispatches_callback(self) -> None:
        received = []
        def callback(payload):
            received.append(payload)
        config = WebhookConfig(callback=callback)
        body = json.dumps({
            "repository": {"full_name": "acme/app"},
            "after": "deadbeef",
        }).encode("utf-8")

        def go(port):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook/github",
                data=body,
                headers={"Content-Type": "application/json", "X-GitHub-Event": "push"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status

        status = self._run_with_server(config, go)
        self.assertEqual(status, 202)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["event"]["provider"], "github")
        self.assertEqual(received[0]["event"]["repo"], "acme/app")

    def test_github_invalid_signature_returns_401(self) -> None:
        config = WebhookConfig(github_secret="topsecret")
        body = json.dumps({"repository": {"full_name": "acme/app"}}).encode("utf-8")

        def go(port):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook/github",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "push",
                    "X-Hub-Signature-256": "sha256=wrong",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=2)
                return None
            except urllib.error.HTTPError as exc:
                return exc.code

        code = self._run_with_server(config, go)
        self.assertEqual(code, 401)

    def test_unknown_event_returns_204(self) -> None:
        config = WebhookConfig()

        def go(port):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook/github",
                data=b'{}',
                headers={"X-GitHub-Event": "watch"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status
        self.assertEqual(self._run_with_server(config, go), 204)

    def test_gitlab_normalizes_event_name(self) -> None:
        received = []
        config = WebhookConfig(callback=lambda p: received.append(p))
        body = json.dumps({
            "project": {"id": 42},
            "object_attributes": {
                "iid": 7, "source_branch": "feature", "target_branch": "main",
                "last_commit": {"id": "abc"},
            },
        }).encode("utf-8")

        def go(port):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook/gitlab",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Gitlab-Event": "Merge Request Hook",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status
        self.assertEqual(self._run_with_server(config, go), 202)
        self.assertEqual(received[0]["event"]["event_type"], "merge_request")
        self.assertEqual(received[0]["event"]["pr_number"], 7)


if __name__ == "__main__":
    unittest.main()
