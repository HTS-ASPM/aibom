"""Tests for P4 — CI evidence + MLflow + risk score + asset graph."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.asset_graph import build_asset_graph, render_asset_graph_json
from aibom.cyclonedx import build_bom
from aibom.evidence.github_actions import collect_github_actions
from aibom.evidence.mlflow import collect_mlflow_runs
from aibom.models import Finding, MatchEvidence
from aibom.risk import score_for_finding, score_per_asset
from aibom.scanner import scan_path


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


class GithubActionsEvidenceTests(unittest.TestCase):
    def test_gpu_runner_detected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / ".github/workflows/train.yml", '''
jobs:
  train:
    runs-on: [self-hosted, gpu, a100]
    steps:
      - run: python train.py
''')
            findings = collect_github_actions(root)
            ids = {f.rule_id for f in findings}
            self.assertIn("gha.runner.gpu", ids)
            self.assertIn("gha.training.entrypoint", ids)

    def test_model_publish_is_high(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / ".github/workflows/release.yml", '''
jobs:
  publish:
    steps:
      - run: huggingface-cli upload owner/model
''')
            findings = collect_github_actions(root)
            pub = [f for f in findings if f.rule_id == "gha.model.publish"]
            self.assertEqual(pub[0].severity, "high")

    def test_no_workflows_returns_empty(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertEqual(collect_github_actions(Path(tmp)), [])


class MlflowEvidenceTests(unittest.TestCase):
    def _write_run(self, root: Path, exp: str, run: str, params: dict, metrics: dict, tags: dict) -> Path:
        run_dir = root / "mlruns" / exp / run
        (run_dir / "params").mkdir(parents=True)
        for k, v in params.items():
            (run_dir / "params" / k).write_text(str(v))
        (run_dir / "metrics").mkdir(parents=True)
        for k, v in metrics.items():
            (run_dir / "metrics" / k).write_text(f"1700000000 {v} 0\n")
        (run_dir / "tags").mkdir(parents=True)
        for k, v in tags.items():
            (run_dir / "tags" / k).write_text(str(v))
        return run_dir

    def test_reads_run_layout(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_run(
                root, "0", "abcdef1234567890",
                params={"lr": 0.001},
                metrics={"loss": 0.42},
                tags={"mlflow.source.git.commit": "deadbeefcafef00d"},
            )
            findings = collect_mlflow_runs(root)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.metadata["params_count"], 1)
            self.assertEqual(f.metadata["metrics_count"], 1)
            self.assertEqual(f.metadata["git_commit"], "deadbeefcafef00d")

    def test_no_mlruns_returns_empty(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertEqual(collect_mlflow_runs(Path(tmp)), [])


class RiskScoreTests(unittest.TestCase):
    def _f(self, **kw):
        defaults = dict(
            finding_id="x", rule_id="r", category="provider", name="OpenAI",
            severity="medium", confidence="high", path="x.py",
            detector="d", entity_type="provider", source_kind="source",
            summary="", evidence=[], metadata={},
        )
        defaults.update(kw)
        return Finding(**defaults)

    def test_critical_finding_scores_high(self) -> None:
        f = self._f(severity="critical", confidence="high")
        self.assertEqual(score_for_finding(f), 30)

    def test_low_confidence_scales_down(self) -> None:
        crit = score_for_finding(self._f(severity="critical", confidence="low"))
        self.assertLess(crit, 30)

    def test_per_asset_groups_and_caps_at_100(self) -> None:
        findings = [
            self._f(severity="critical", confidence="high",
                    metadata={"owasp_llm": ["LLM01", "LLM06", "LLM08"], "mitre_atlas": ["AML.T0051", "AML.T0048"]}),
            self._f(severity="high", confidence="high"),
            self._f(severity="high", confidence="high"),
        ]
        risks = score_per_asset(findings)
        self.assertEqual(len(risks), 1)
        self.assertLessEqual(risks[0].score, 100)
        self.assertGreater(risks[0].score, 30)
        component_names = {name for name, _ in risks[0].components}
        self.assertIn("framework_boost", component_names)

    def test_secret_kicker(self) -> None:
        secret = self._f(category="secret", rule_id="secret.ai_key.pattern", severity="high")
        risks = score_per_asset([secret])
        kicker_added = any(name == "secret_kicker" for name, _ in risks[0].components)
        self.assertTrue(kicker_added)


class AssetGraphTests(unittest.TestCase):
    def test_graph_has_root_and_assets(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "from openai import OpenAI\nimport pinecone\n",
                encoding="utf-8",
            )
            result = scan_path(root)
            graph = build_asset_graph(result, include_findings=True)
            node_types = {n["type"] for n in graph["nodes"]}
            self.assertIn("application", node_types)
            self.assertIn("provider", node_types)
            self.assertIn("finding", node_types)

    def test_findings_link_to_assets(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("from openai import OpenAI\n", encoding="utf-8")
            result = scan_path(root)
            graph = build_asset_graph(result)
            affects_edges = [e for e in graph["edges"] if e["kind"] == "affects"]
            self.assertTrue(affects_edges)

    def test_render_returns_valid_json(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("from openai import OpenAI\n", encoding="utf-8")
            result = scan_path(root)
            payload = json.loads(render_asset_graph_json(result))
            self.assertIn("nodes", payload)
            self.assertIn("edges", payload)


class CdxIntegrationTests(unittest.TestCase):
    def test_risk_score_property_on_components(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("from openai import OpenAI\n", encoding="utf-8")
            result = scan_path(root)
            bom = build_bom(result)
            scored = False
            for component in bom["components"] + bom["services"]:
                for prop in component.get("properties", []):
                    if prop["name"] == "aibom:risk_score":
                        scored = True
                        self.assertTrue(prop["value"].isdigit())
            self.assertTrue(scored, "expected aibom:risk_score on at least one component/service")


if __name__ == "__main__":
    unittest.main()
