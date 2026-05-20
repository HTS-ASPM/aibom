"""Tests for the dataset detector."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.cyclonedx import build_bom
from aibom.datasets import scan_datasets
from aibom.scanner import scan_path


class DatasetRulesTests(unittest.TestCase):
    def _scan(self, body: str) -> list:
        return scan_datasets("file.py", body.splitlines(), source_kind="source")

    def test_huggingface_load_dataset(self) -> None:
        findings = self._scan("from datasets import load_dataset\nds = load_dataset('squad')")
        rules = {f.rule_id for f in findings}
        self.assertIn("dataset.huggingface.load", rules)

    def test_s3_uri(self) -> None:
        findings = self._scan("path = 's3://mybucket/training/v1.parquet'")
        self.assertTrue(any(f.rule_id == "dataset.s3.uri" for f in findings))

    def test_gcs_and_azure(self) -> None:
        gcs = self._scan("p = 'gs://mybucket/data.csv'")
        az = self._scan("p = 'wasbs://container@acct.blob.core.windows.net/path'")
        self.assertTrue(any(f.rule_id == "dataset.gcs.uri" for f in gcs))
        self.assertTrue(any(f.rule_id == "dataset.azure_blob.uri" for f in az))

    def test_bigquery_table(self) -> None:
        findings = self._scan("query = 'SELECT * FROM `proj.ds.tbl` WHERE id IS NOT NULL'")
        self.assertTrue(any(f.rule_id == "dataset.bigquery.table" for f in findings))

    def test_snowflake_client(self) -> None:
        findings = self._scan("import snowflake.connector as sf")
        self.assertTrue(any(f.rule_id == "dataset.snowflake.client" for f in findings))

    def test_parquet_and_delta(self) -> None:
        parquet = self._scan("df = pd.read_parquet('train.parquet')")
        delta = self._scan("dt = DeltaTable.forPath(spark, 'path')")
        self.assertTrue(any(f.rule_id == "dataset.parquet.read" for f in parquet))
        self.assertTrue(any(f.rule_id == "dataset.delta.uri" for f in delta))

    def test_dvc_and_lakefs(self) -> None:
        dvc = self._scan("import dvc.api\nwith dvc.api.open('data.csv') as f: ...")
        lakefs = self._scan("path = 'lakefs://repo/main/data.csv'")
        self.assertTrue(any(f.rule_id == "dataset.dvc" for f in dvc))
        self.assertTrue(any(f.rule_id == "dataset.lakefs.uri" for f in lakefs))


class DatasetCdxIntegrationTests(unittest.TestCase):
    def test_dataset_becomes_data_component(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "train.py").write_text(
                "from datasets import load_dataset\n"
                "ds = load_dataset('squad')\n"
                "path = 's3://mybucket/train.parquet'\n",
                encoding="utf-8",
            )
            result = scan_path(root)
            bom = build_bom(result)
            data_components = [c for c in bom["components"] if c["type"] == "data"]
            self.assertTrue(data_components, "expected dataset data components")
            classifications = {c["data"][0]["classification"] for c in data_components}
            # Should contain at least one of our dataset classifications
            self.assertTrue(
                {"object-store", "huggingface-hub"} & classifications,
                f"expected object-store or huggingface-hub classification, got {classifications}",
            )


class DatasetIsolationDemotionTests(unittest.TestCase):
    """Dataset rules emit info-level findings in isolation, but preserve
    their original severity when the same file also touches an LLM
    provider (real data-flow risk)."""

    def test_dataset_only_file_demoted_to_info(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "load.py").write_text(
                "path = 's3://mybucket/train.parquet'\n",
                encoding="utf-8",
            )
            result = scan_path(root)
            dataset_findings = [f for f in result.findings if f.rule_id.startswith("dataset.")]
            self.assertTrue(dataset_findings, "expected at least one dataset finding")
            for finding in dataset_findings:
                self.assertEqual(
                    finding.severity, "info",
                    f"{finding.rule_id} on {finding.path} should be demoted to info",
                )
                # The original severity should be recorded for audit when it was demoted.
                self.assertEqual(finding.metadata.get("original_severity"), "medium")

    def test_dataset_plus_provider_preserves_severity(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "train.py").write_text(
                "import openai\n"
                "path = 's3://mybucket/train.parquet'\n"
                "client = openai.OpenAI()\n",
                encoding="utf-8",
            )
            result = scan_path(root)
            s3_findings = [f for f in result.findings if f.rule_id == "dataset.s3.uri"]
            self.assertTrue(s3_findings, "expected an S3 dataset finding")
            for finding in s3_findings:
                self.assertEqual(
                    finding.severity, "medium",
                    "dataset finding in a file with a provider should keep original severity",
                )
                self.assertNotIn("original_severity", finding.metadata)


if __name__ == "__main__":
    unittest.main()
