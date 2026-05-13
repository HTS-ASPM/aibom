"""Tests for the model-artifact inspector."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.artifacts import (
    find_artifacts,
    scan_artifacts,
)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _safetensors_blob() -> bytes:
    """Minimal valid safetensors header: 8-byte little-endian header length + JSON header."""
    header = b'{"__metadata__":{}}'
    return struct.pack("<Q", len(header)) + header


class ArtifactDiscoveryTests(unittest.TestCase):
    def test_finds_pickle_and_safetensors(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "models" / "model.pkl", b"\x80\x04N.")
            _write(root / "models" / "model.safetensors", _safetensors_blob())
            _write(root / "models" / "model.onnx", b"ONNX-FAKE")
            _write(root / "models" / "model.gguf", b"GGUF\x00\x00\x00\x00")

            candidates = find_artifacts(root)
            formats = sorted(c.format_label for c in candidates)
            self.assertEqual(formats, ["gguf", "onnx", "pickle", "safetensors"])

    def test_severity_routing(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "ckpt.pt", b"\x80\x04N.")
            _write(root / "weights.safetensors", _safetensors_blob())
            findings = scan_artifacts(root, run_modelscan=False)
            sev = {f.metadata["format"]: f.severity for f in findings}
            self.assertEqual(sev["torch-pickle"], "high")
            self.assertEqual(sev["safetensors"], "info")

    def test_skips_dot_dirs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / ".git" / "objects" / "weird.pkl", b"\x80\x04N.")
            _write(root / ".venv" / "site-packages" / "model.pt", b"\x80\x04N.")
            _write(root / "real.pkl", b"\x80\x04N.")
            findings = scan_artifacts(root, run_modelscan=False)
            paths = sorted(f.path for f in findings)
            self.assertEqual(paths, ["real.pkl"])

    def test_hf_bin_only_when_neighbored_by_config(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Lone .bin: should NOT be reported (avoids generic .bin noise).
            _write(root / "stuff" / "blob.bin", b"\x00" * 32)
            # .bin next to config.json: HF-style weight, MUST be reported.
            _write(root / "model" / "pytorch_model.bin", b"\x80\x04N.")
            _write(root / "model" / "config.json", b"{}")
            findings = scan_artifacts(root, run_modelscan=False)
            paths = sorted(f.path for f in findings)
            self.assertEqual(paths, ["model/pytorch_model.bin"])
            hf = next(f for f in findings if "pytorch_model" in f.path)
            self.assertEqual(hf.metadata["format"], "hf-bin")
            self.assertEqual(hf.severity, "medium")

    def test_finding_carries_sha256(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "m.safetensors", _safetensors_blob())
            findings = scan_artifacts(root, run_modelscan=False)
            self.assertEqual(len(findings), 1)
            sha = findings[0].metadata["sha256"]
            self.assertEqual(len(sha), 64)


class ArtifactCdxIntegrationTests(unittest.TestCase):
    """Verify the artifact inspector composes cleanly with the CDX emitter."""

    def test_artifact_becomes_machine_learning_model_with_hash(self) -> None:
        from aibom.cyclonedx import build_bom
        from aibom.scanner import scan_path

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "weights.safetensors", _safetensors_blob())
            result = scan_path(root)
            bom = build_bom(result)
            ml_models = [c for c in bom["components"] if c["type"] == "machine-learning-model"]
            self.assertTrue(ml_models, "expected at least one ML model component from the artifact scan")
            primary = ml_models[0]
            self.assertIn("hashes", primary)
            self.assertEqual(primary["hashes"][0]["alg"], "SHA-256")
            self.assertEqual(len(primary["hashes"][0]["content"]), 64)


if __name__ == "__main__":
    unittest.main()
