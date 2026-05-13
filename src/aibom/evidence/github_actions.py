"""GitHub Actions workflow inspector.

Surfaces ML/training-related CI signals that should land in CycloneDX
`formulation` for an Annex-IV-grade BOM:

  - GPU-class self-hosted runners (\\[self-hosted, gpu...\\])
  - Steps that invoke training (`python train.py`, `accelerate launch`,
    `torchrun`, `deepspeed`)
  - Steps that pull HuggingFace models / datasets at build time
  - Steps that push to a model registry (\\`hf-cli upload\\`,
    `mlflow models register`, AWS SageMaker model package)
  - Container image references with AI signal (delegates to the same
    helper IaC's helm_k8s parser uses)

Pure regex over raw YAML — no PyYAML dep — same approach as the helm/k8s
parser. This keeps the scanner free of optional deps.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.models import Finding, MatchEvidence


_WORKFLOW_DIR = Path(".github/workflows")


_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("gha.runner.gpu", "GPU runner declared in workflow", "medium",
     re.compile(r"runs-on:\s*\[?[^\n\]]*\b(gpu|a100|h100|t4|l4|nvidia)\b", re.IGNORECASE)),

    ("gha.training.entrypoint", "Workflow runs a model training entrypoint", "medium",
     re.compile(r"\b(accelerate\s+launch|torchrun|deepspeed|python\s+train(?:ing)?\.py|python\s+-m\s+train)", re.IGNORECASE)),

    ("gha.hf.download", "Workflow downloads HF model / dataset at build", "low",
     re.compile(r"\b(huggingface[-_]hub|hf\s+download|snapshot_download|load_dataset)\b", re.IGNORECASE)),

    ("gha.model.publish", "Workflow publishes a model to a registry", "high",
     re.compile(
         r"\b(hf\s+upload|huggingface-cli\s+upload|"
         r"mlflow\s+models\s+register|"
         r"aws\s+sagemaker\s+create-model|"
         r"gcloud\s+ai\s+models\s+upload|"
         r"az\s+ml\s+model\s+(?:create|register))\b",
         re.IGNORECASE,
     )),

    ("gha.dataset.upload", "Workflow uploads a training/eval dataset", "medium",
     re.compile(r"\b(aws\s+s3\s+(?:cp|sync)|gsutil\s+(?:cp|rsync)|az\s+storage\s+blob\s+upload)\b.*\b(dataset|train|eval)\b", re.IGNORECASE)),
]


def collect_github_actions(root: Path) -> list[Finding]:
    if not root.exists():
        return []
    workflow_root = root / _WORKFLOW_DIR
    if not workflow_root.exists() or not workflow_root.is_dir():
        return []
    findings: list[Finding] = []
    for path in workflow_root.glob("*.yml"):
        findings.extend(_scan_workflow(path, root))
    for path in workflow_root.glob("*.yaml"):
        findings.extend(_scan_workflow(path, root))
    return findings


def _scan_workflow(path: Path, root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    rel_path = _rel(path, root)
    findings: list[Finding] = []
    for rule_id, summary, severity, pattern in _RULES:
        evidence: list[MatchEvidence] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                evidence.append(MatchEvidence(line=line_no, snippet=line[:220], match=rule_id.split(".")[-1]))
                if len(evidence) >= 3:
                    break
        if evidence:
            findings.append(
                Finding(
                    finding_id=f"evidence.gha:{rule_id}:{rel_path}",
                    rule_id=rule_id,
                    category="formulation",
                    name=summary,
                    severity=severity,
                    confidence="high",
                    path=rel_path,
                    detector="gha-evidence",
                    entity_type="ci",
                    source_kind="ci",
                    summary=summary,
                    evidence=evidence,
                    metadata={"workflow": path.name, "evidence_kind": "github-actions"},
                )
            )
    return findings


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
