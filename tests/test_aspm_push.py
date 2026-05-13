"""Tests for the P3 ASPM / Dependency-Track push transport."""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from aibom.aspm_push import (
    PushError,
    PushResponse,
    push_to_aspm,
    push_to_dependency_track,
)


def _capturing_requester(captured: dict, *, status: int = 202, body: str = ""):
    def requester(url, payload, headers):
        captured["url"] = url
        captured["payload"] = payload
        captured["headers"] = headers
        return PushResponse(status=status, body=body)
    return requester


class PushAspmTests(unittest.TestCase):
    def test_posts_cdx_payload_with_bearer_token(self) -> None:
        captured: dict = {}
        with mock.patch.dict(os.environ, {"ASPM_TOKEN": "tok-abc"}):
            response = push_to_aspm(
                "https://aspm.example/aibom/ingest",
                {"bomFormat": "CycloneDX", "specVersion": "1.6"},
                project="acme/app",
                requester=_capturing_requester(captured),
            )
        self.assertEqual(response.status, 202)
        self.assertEqual(captured["url"], "https://aspm.example/aibom/ingest")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer tok-abc")
        self.assertEqual(captured["headers"]["Content-Type"], "application/vnd.cyclonedx+json")
        self.assertEqual(captured["headers"]["X-Aibom-Project"], "acme/app")
        body = json.loads(captured["payload"])
        self.assertEqual(body["specVersion"], "1.6")

    def test_no_token_in_env_omits_authorization_header(self) -> None:
        captured: dict = {}
        with mock.patch.dict(os.environ, {}, clear=True):
            push_to_aspm(
                "https://aspm.example/ingest",
                {"bomFormat": "CycloneDX"},
                requester=_capturing_requester(captured),
            )
        self.assertNotIn("Authorization", captured["headers"])

    def test_4xx_raises_push_error(self) -> None:
        captured: dict = {}
        with self.assertRaises(PushError):
            push_to_aspm(
                "https://aspm.example/ingest",
                {"bomFormat": "CycloneDX"},
                requester=_capturing_requester(captured, status=403, body="forbidden"),
            )


class PushDependencyTrackTests(unittest.TestCase):
    def test_wraps_bom_in_base64_envelope(self) -> None:
        captured: dict = {}
        with mock.patch.dict(os.environ, {"DEPENDENCY_TRACK_API_KEY": "dt-key"}):
            push_to_dependency_track(
                "https://dt.example/",
                {"bomFormat": "CycloneDX", "specVersion": "1.6"},
                project_id="proj-uuid",
                requester=_capturing_requester(captured),
            )
        self.assertEqual(captured["url"], "https://dt.example/api/v1/bom")
        self.assertEqual(captured["headers"]["X-Api-Key"], "dt-key")
        body = json.loads(captured["payload"])
        self.assertEqual(body["project"], "proj-uuid")
        # base64 of the BOM
        import base64
        decoded = json.loads(base64.b64decode(body["bom"]).decode("utf-8"))
        self.assertEqual(decoded["specVersion"], "1.6")

    def test_missing_api_key_raises(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(PushError):
                push_to_dependency_track(
                    "https://dt.example/",
                    {"bomFormat": "CycloneDX"},
                    project_id="proj-uuid",
                )


if __name__ == "__main__":
    unittest.main()
