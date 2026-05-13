"""MLflow run-folder inspector.

Reads the on-disk `mlruns/` layout (without requiring the `mlflow`
package or a tracking-server connection) and surfaces every run as a
`formulation` finding the CDX emitter can attach to the corresponding
machine-learning-model component.

MLflow's filesystem layout (v1+):

    mlruns/
      <experiment_id>/
        meta.yaml
        <run_id>/
          meta.yaml
          params/<name>     -- contents = value
          metrics/<name>    -- contents = list of (timestamp value step) lines
          tags/<name>       -- contents = value
          artifacts/...
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aibom.models import Finding, MatchEvidence


@dataclass
class MlflowRun:
    experiment_id: str
    run_id: str
    params: dict[str, str]
    metrics: dict[str, float]
    tags: dict[str, str]
    artifact_count: int


def collect_mlflow_runs(root: Path, *, mlruns_dir: Path | None = None, max_runs: int = 100) -> list[Finding]:
    runs_root = mlruns_dir or (root / "mlruns")
    if not runs_root.exists() or not runs_root.is_dir():
        return []
    findings: list[Finding] = []
    runs = []
    for experiment_dir in sorted(runs_root.iterdir()):
        if not experiment_dir.is_dir() or experiment_dir.name == ".trash":
            continue
        for run_dir in sorted(experiment_dir.iterdir()):
            if not run_dir.is_dir() or run_dir.name == "meta.yaml":
                continue
            run = _read_run(experiment_dir.name, run_dir)
            if run is not None:
                runs.append((run, run_dir))
                if len(runs) >= max_runs:
                    break
        if len(runs) >= max_runs:
            break

    for run, run_dir in runs:
        findings.append(_finding_for_run(run, run_dir, root))
    return findings


def _read_run(experiment_id: str, run_dir: Path) -> MlflowRun | None:
    params = _read_kv(run_dir / "params")
    metrics = _read_metrics(run_dir / "metrics")
    tags = _read_kv(run_dir / "tags")
    artifact_count = _count_artifacts(run_dir / "artifacts")
    return MlflowRun(
        experiment_id=experiment_id,
        run_id=run_dir.name,
        params=params,
        metrics=metrics,
        tags=tags,
        artifact_count=artifact_count,
    )


def _read_kv(path: Path) -> dict[str, str]:
    if not path.exists() or not path.is_dir():
        return {}
    out: dict[str, str] = {}
    for f in path.iterdir():
        if not f.is_file():
            continue
        try:
            out[f.name] = f.read_text(encoding="utf-8").strip()[:512]
        except (OSError, UnicodeDecodeError):
            continue
    return out


def _read_metrics(path: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    if not path.exists() or not path.is_dir():
        return out
    for f in path.iterdir():
        if not f.is_file():
            continue
        try:
            lines = [l for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
        except (OSError, UnicodeDecodeError):
            continue
        if not lines:
            continue
        last = lines[-1].split()
        try:
            out[f.name] = float(last[1])
        except (IndexError, ValueError):
            continue
    return out


def _count_artifacts(path: Path) -> int:
    if not path.exists() or not path.is_dir():
        return 0
    return sum(1 for _ in path.rglob("*") if _.is_file())


def _finding_for_run(run: MlflowRun, run_dir: Path, root: Path) -> Finding:
    rel = _rel(run_dir, root)
    summary_bits: list[str] = []
    if run.tags.get("mlflow.source.git.commit"):
        summary_bits.append(f"commit={run.tags['mlflow.source.git.commit'][:8]}")
    if run.metrics:
        summary_bits.append(", ".join(f"{k}={v:g}" for k, v in list(run.metrics.items())[:3]))
    summary = "MLflow training run — " + ("; ".join(summary_bits) if summary_bits else "no metrics yet")
    return Finding(
        finding_id=f"evidence.mlflow:{run.experiment_id}:{run.run_id}",
        rule_id="evidence.mlflow.run",
        category="formulation",
        name=f"MLflow run {run.run_id[:12]}",
        severity="info",
        confidence="high",
        path=rel,
        detector="mlflow-evidence",
        entity_type="training_run",
        source_kind="ci",
        summary=summary,
        evidence=[
            MatchEvidence(
                line=0,
                snippet=f"params={len(run.params)} metrics={len(run.metrics)} artifacts={run.artifact_count}",
                match=run.run_id[:12],
            )
        ],
        metadata={
            "evidence_kind": "mlflow",
            "experiment_id": run.experiment_id,
            "run_id": run.run_id,
            "params_count": len(run.params),
            "metrics_count": len(run.metrics),
            "artifact_count": run.artifact_count,
            "framework": run.tags.get("mlflow.source.type", ""),
            "git_commit": run.tags.get("mlflow.source.git.commit", ""),
        },
    )


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
