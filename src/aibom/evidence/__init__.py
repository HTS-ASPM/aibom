"""Evidence collectors — feed CycloneDX `formulation` and `evidence`
blocks with the build-time / runtime context EU AI Act Annex IV asks for.

Each collector exposes `collect(root: Path) -> list[Finding]` and is
opt-in via the scanner pipeline (cheap to skip when not needed).
"""

from aibom.evidence.github_actions import collect_github_actions
from aibom.evidence.mlflow import collect_mlflow_runs

__all__ = ["collect_github_actions", "collect_mlflow_runs"]
