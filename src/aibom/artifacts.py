"""Model-artifact inspector.

Walks a path for binary model files, hashes them, and emits findings
keyed by file format risk:

  pickle / pt / pth        -> HIGH    (arbitrary code execution on load)
  h5 / keras / hdf5        -> MEDIUM  (Lambda layer code-exec risk)
  pb (TensorFlow SavedModel) -> MEDIUM
  onnx                     -> LOW     (graph format, but external custom ops)
  gguf / ggml              -> LOW     (llama.cpp tensor format)
  safetensors              -> INFO    (safe by design — header-only metadata)
  bin (when adjacent to    -> MEDIUM  (HF/PyTorch convention; format unknown)
        config.json / tokenizer.json)

If `modelscan` (Apache-2.0, https://github.com/protectai/modelscan) is
importable in the host environment, we additionally invoke it for each
candidate file and surface its issues as separate findings under the
`model_artifact.modelscan` rule. modelscan is *optional* — we never add
it as a hard dependency.

Note on pickle scanners: PickleScan/ModelScan use denylists and have
documented bypasses (JFrog, Sonatype). Hash + format-risk classification
is independently useful even when modelscan reports clean.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from aibom.models import Finding, MatchEvidence


_MODEL_EXTENSIONS: dict[str, tuple[str, str, str]] = {
    # extension -> (format_label, severity, description)
    ".pkl": ("pickle", "high", "Pickle file — arbitrary code execution on load"),
    ".pickle": ("pickle", "high", "Pickle file — arbitrary code execution on load"),
    ".pt": ("torch-pickle", "high", "PyTorch checkpoint (pickle) — arbitrary code execution on load"),
    ".pth": ("torch-pickle", "high", "PyTorch checkpoint (pickle) — arbitrary code execution on load"),
    ".h5": ("h5", "medium", "Keras/HDF5 weights — Lambda layer code-exec risk"),
    ".hdf5": ("h5", "medium", "Keras/HDF5 weights — Lambda layer code-exec risk"),
    ".keras": ("keras", "medium", "Keras v3 archive — config + weights"),
    ".pb": ("tf-pb", "medium", "TensorFlow SavedModel / GraphDef"),
    ".onnx": ("onnx", "low", "ONNX graph — risk only via external custom ops"),
    ".gguf": ("gguf", "low", "GGUF tensor file (llama.cpp / Ollama)"),
    ".ggml": ("ggml", "low", "GGML tensor file (legacy llama.cpp)"),
    ".safetensors": ("safetensors", "info", "Safetensors — header-only metadata, safe by design"),
}

# `.bin` is overloaded; only flag when it sits next to a HF-style config
_BIN_NEIGHBOR_FILES = {"config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors.index.json"}


@dataclass(frozen=True, slots=True)
class ArtifactCandidate:
    path: Path
    rel_path: str
    format_label: str
    severity: str
    description: str


def find_artifacts(root: Path, max_bytes: int | None = None) -> list[ArtifactCandidate]:
    """Walk `root` for binary model files. `max_bytes` skips files above the cap (per file)."""
    candidates: list[ArtifactCandidate] = []
    if not root.exists():
        return candidates
    if root.is_file():
        candidate = _classify_file(root, root.parent)
        if candidate:
            candidates.append(candidate)
        return candidates
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part.startswith(".") and part not in {".", ".."} for part in path.relative_to(root).parts):
            continue  # skip dot-dirs (.git, .venv, ...)
        if max_bytes is not None:
            try:
                if path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
        candidate = _classify_file(path, root)
        if candidate:
            candidates.append(candidate)
    return candidates


def scan_artifacts(root: Path, max_bytes: int | None = None, run_modelscan: bool = True) -> list[Finding]:
    """Build Finding objects for every detected model artifact."""
    findings: list[Finding] = []
    for candidate in find_artifacts(root, max_bytes=max_bytes):
        digest = _sha256(candidate.path)
        findings.append(
            Finding(
                finding_id=f"model_artifact:{candidate.format_label}:{digest[:16]}",
                rule_id="model_artifact.format",
                category="model_artifact",
                name=candidate.path.name,
                severity=candidate.severity,
                confidence="high",
                path=candidate.rel_path,
                detector="artifact-inspector",
                entity_type="model_artifact",
                source_kind="binary",
                summary=candidate.description,
                evidence=[MatchEvidence(line=0, snippet=f"sha256:{digest}", match=candidate.format_label)],
                metadata={
                    "format": candidate.format_label,
                    "sha256": digest,
                    "size_bytes": candidate.path.stat().st_size,
                },
            )
        )
        if run_modelscan and candidate.format_label in {"pickle", "torch-pickle", "h5", "keras", "tf-pb"}:
            findings.extend(_run_modelscan(candidate))
    return findings


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _classify_file(path: Path, root: Path) -> ArtifactCandidate | None:
    suffix = path.suffix.lower()
    if suffix in _MODEL_EXTENSIONS:
        label, severity, desc = _MODEL_EXTENSIONS[suffix]
        return ArtifactCandidate(
            path=path,
            rel_path=_rel(path, root),
            format_label=label,
            severity=severity,
            description=desc,
        )
    if suffix == ".bin" and _looks_like_hf_weight(path):
        return ArtifactCandidate(
            path=path,
            rel_path=_rel(path, root),
            format_label="hf-bin",
            severity="medium",
            description="HuggingFace .bin weight (likely pickle) — arbitrary code execution on load",
        )
    return None


def _looks_like_hf_weight(path: Path) -> bool:
    try:
        siblings = {p.name for p in path.parent.iterdir() if p.is_file()}
    except OSError:
        return False
    return bool(_BIN_NEIGHBOR_FILES & siblings)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _sha256(path: Path, *, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _run_modelscan(candidate: ArtifactCandidate) -> Iterable[Finding]:
    try:
        from modelscan.modelscan import ModelScan  # type: ignore
    except ImportError:
        return []
    try:
        scanner = ModelScan()
        report = scanner.scan(str(candidate.path))
    except Exception as exc:  # noqa: BLE001 — modelscan errors are diverse
        return [
            Finding(
                finding_id=f"model_artifact.modelscan.error:{candidate.rel_path}",
                rule_id="model_artifact.modelscan.error",
                category="model_artifact",
                name=f"modelscan error on {candidate.path.name}",
                severity="info",
                confidence="low",
                path=candidate.rel_path,
                detector="modelscan-adapter",
                entity_type="model_artifact",
                source_kind="binary",
                summary=f"modelscan failed: {exc}",
                evidence=[],
                metadata={"format": candidate.format_label},
            )
        ]
    issues = report.get("issues") if isinstance(report, dict) else getattr(report, "issues", [])
    findings: list[Finding] = []
    for issue in issues or []:
        sev = (issue.get("severity") if isinstance(issue, dict) else getattr(issue, "severity", "")).lower()
        severity = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}.get(sev, "medium")
        message = issue.get("description") if isinstance(issue, dict) else getattr(issue, "description", "")
        findings.append(
            Finding(
                finding_id=f"model_artifact.modelscan:{candidate.rel_path}:{hash(message)}",
                rule_id="model_artifact.modelscan",
                category="model_artifact",
                name=f"modelscan: {message[:60]}",
                severity=severity,
                confidence="high",
                path=candidate.rel_path,
                detector="modelscan-adapter",
                entity_type="model_artifact",
                source_kind="binary",
                summary=str(message),
                evidence=[],
                metadata={"format": candidate.format_label, "tool": "modelscan"},
            )
        )
    return findings
