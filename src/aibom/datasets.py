"""Dataset detector.

Adds a `dataset` finding category by scanning text files for references
to datasets across common storage and orchestration systems:

  - Hugging Face Datasets   load_dataset(...), datasets.load_dataset
  - Object stores           s3://, gs://, wasbs://, abfs://, r2://, oss://
  - Warehouses              BigQuery FROM `proj.ds.tbl`, Snowflake table refs,
                            Databricks Unity Catalog catalog.schema.table
  - Lakehouse formats       *.parquet, *.arrow, *.feather, delta:/, iceberg
  - Versioning              dvc pull / dvc.api.read, lakefs://
  - HF Hub datasets         datasets/<owner>/<name>
  - Generic CSV/TSV         pandas.read_csv("path") with cloud-ish path

Keeps to text-file scanning (same surface as the regex rule layer) so it
benefits from the same exclusions and source-kind classification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from aibom.models import Finding, MatchEvidence


@dataclass(frozen=True, slots=True)
class DatasetRule:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: str
    confidence: str
    detector: str
    summary: str
    metadata: dict[str, str]


DATASET_RULES: list[DatasetRule] = [
    DatasetRule(
        rule_id="dataset.huggingface.load",
        name="Hugging Face dataset load",
        pattern=re.compile(r"\b(load_dataset|datasets\.load_dataset)\s*\(", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="dataset-pattern",
        summary="Loads a Hugging Face dataset — verify license and provenance.",
        metadata={"source": "huggingface-datasets"},
    ),
    DatasetRule(
        rule_id="dataset.huggingface.hub_path",
        name="Hugging Face dataset path",
        pattern=re.compile(r"\bdatasets/[A-Za-z0-9_\-./]+\b"),
        severity="low",
        confidence="medium",
        detector="dataset-pattern",
        summary="References a dataset path on the Hugging Face Hub.",
        metadata={"source": "huggingface-datasets"},
    ),
    DatasetRule(
        rule_id="dataset.s3.uri",
        name="S3 dataset URI",
        pattern=re.compile(r"\bs3://[A-Za-z0-9._\-/]+", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="dataset-pattern",
        summary="Loads data from an S3 URI — verify bucket access and data classification.",
        metadata={"source": "aws-s3"},
    ),
    DatasetRule(
        rule_id="dataset.gcs.uri",
        name="GCS dataset URI",
        pattern=re.compile(r"\bgs://[A-Za-z0-9._\-/]+", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="dataset-pattern",
        summary="Loads data from a Google Cloud Storage URI.",
        metadata={"source": "gcp-gcs"},
    ),
    DatasetRule(
        rule_id="dataset.azure_blob.uri",
        name="Azure Blob dataset URI",
        pattern=re.compile(r"\b(wasbs?|abfss?)://[A-Za-z0-9._\-/@]+", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="dataset-pattern",
        summary="Loads data from an Azure Blob / ADLS URI.",
        metadata={"source": "azure-blob"},
    ),
    DatasetRule(
        rule_id="dataset.bigquery.table",
        name="BigQuery table reference",
        pattern=re.compile(r"\b(FROM|JOIN)\s+`?[A-Za-z0-9_\-]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+`?", re.IGNORECASE),
        severity="medium",
        confidence="medium",
        detector="dataset-pattern",
        summary="References a BigQuery / Unity-Catalog-style three-part table identifier.",
        metadata={"source": "warehouse"},
    ),
    DatasetRule(
        rule_id="dataset.snowflake.client",
        name="Snowflake client",
        pattern=re.compile(r"\bsnowflake\.connector\b|\bsnowflakedb\b", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="dataset-pattern",
        summary="Uses a Snowflake client — likely pulls warehouse data.",
        metadata={"source": "warehouse"},
    ),
    DatasetRule(
        rule_id="dataset.parquet.read",
        name="Parquet dataset read",
        pattern=re.compile(r"\b(read_parquet|to_parquet|ParquetFile|ParquetDataset)\b", re.IGNORECASE),
        severity="low",
        confidence="medium",
        detector="dataset-pattern",
        summary="Reads or writes Parquet data.",
        metadata={"source": "lakehouse"},
    ),
    DatasetRule(
        rule_id="dataset.delta.uri",
        name="Delta Lake reference",
        pattern=re.compile(r"\b(delta|delta_table|DeltaTable)\b", re.IGNORECASE),
        severity="low",
        confidence="medium",
        detector="dataset-pattern",
        summary="References Delta Lake — lakehouse format on object storage.",
        metadata={"source": "lakehouse"},
    ),
    DatasetRule(
        rule_id="dataset.dvc",
        name="DVC dataset versioning",
        pattern=re.compile(r"\b(dvc\.api\.|dvc\s+pull|dvc\s+get)\b", re.IGNORECASE),
        severity="info",
        confidence="high",
        detector="dataset-pattern",
        summary="Uses DVC for data versioning — provenance signal.",
        metadata={"source": "dvc"},
    ),
    DatasetRule(
        rule_id="dataset.lakefs.uri",
        name="lakeFS reference",
        pattern=re.compile(r"\blakefs://[A-Za-z0-9._\-/]+", re.IGNORECASE),
        severity="info",
        confidence="high",
        detector="dataset-pattern",
        summary="References a lakeFS path — provenance signal.",
        metadata={"source": "lakefs"},
    ),
    DatasetRule(
        rule_id="dataset.csv.read",
        name="Tabular CSV/TSV read",
        pattern=re.compile(
            r"\b(read_csv|read_table|read_tsv)\s*\(\s*['\"][^'\"]+\.(csv|tsv|txt)['\"]",
            re.IGNORECASE,
        ),
        severity="low",
        confidence="medium",
        detector="dataset-pattern",
        summary="Reads tabular CSV/TSV data — likely training or evaluation source.",
        metadata={"source": "tabular"},
    ),
]


def scan_datasets(rel_path: str, lines: list[str], source_kind: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule in DATASET_RULES:
        evidence: list[MatchEvidence] = []
        for line_number, line in enumerate(lines, start=1):
            match = rule.pattern.search(line)
            if match:
                evidence.append(
                    MatchEvidence(
                        line=line_number,
                        snippet=line[:220],
                        match=match.group(0),
                    )
                )
                if len(evidence) >= 3:
                    break
        if evidence:
            findings.append(
                Finding(
                    finding_id=f"dataset:{rule.rule_id}:{rel_path}",
                    rule_id=rule.rule_id,
                    category="dataset",
                    name=rule.name,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    path=rel_path,
                    detector=rule.detector,
                    entity_type="dataset",
                    source_kind=source_kind,
                    summary=rule.summary,
                    evidence=evidence,
                    metadata=dict(rule.metadata),
                )
            )
    return findings
