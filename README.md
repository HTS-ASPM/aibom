# AiBOM

AiBOM is a repository scanner that discovers AI-related components and produces a lightweight AI Bill of Materials with risk-oriented findings.

## MVP coverage

- LLM providers and model references
- Manifest-aware dependency detection for `requirements.txt`, `pyproject.toml`, `package.json`, and `go.mod`
- SDK and agent framework patterns
- Vector databases and embedding usage
- RAG pipeline signals
- Prompt and system prompt patterns
- AI-related environment variable references
- External AI API endpoints
- Likely business-data-to-AI flow correlation

## Usage

```bash
PYTHONPATH=src python3 -m aibom scan . --format json
PYTHONPATH=src python3 -m aibom scan . --format markdown --output report.md
PYTHONPATH=src python3 -m aibom scan . --format sarif --output report.sarif
PYTHONPATH=src python3 -m aibom scan . --format cyclonedx --output bom.cdx.json
PYTHONPATH=src python3 -m aibom scan . --exclude "README.md" --exclude "tests/*"
PYTHONPATH=src python3 -m aibom scan-github openai/openai-python --ref main --format json
PYTHONPATH=src python3 -m aibom scan-huggingface mistralai/Mistral-7B-v0.1 --format json
PYTHONPATH=src python3 -m aibom scan-aws dev --region us-east-1 --format json
PYTHONPATH=src python3 -m aibom scan-azure dev --subscription-id sub-123 --format json
PYTHONPATH=src python3 -m aibom scan-gcp dev --project-id proj-123 --format json
PYTHONPATH=src python3 -m aibom scan . --policy tests/fixtures/policy.toml --format json
PYTHONPATH=src python3 -m aibom scan . --tuning tests/fixtures/tuning.toml --format json
PYTHONPATH=src python3 -m aibom scan . --save
PYTHONPATH=src python3 -m aibom history --limit 10
PYTHONPATH=src python3 -m aibom show-scan <scan-id> --format markdown
PYTHONPATH=src python3 -m aibom diff-scans <older-scan-id> <newer-scan-id>
```

The CLI also keeps backward compatibility with the older style:

```bash
PYTHONPATH=src python3 -m aibom .
```

## Output

- `json`: machine-readable findings
- `markdown`: human-readable report
- `sarif`: security-tooling compatible findings
- `cyclonedx`: CycloneDX 1.6 ML-BOM (machine-learning-model components with `modelCard`, `service` components for providers / vector DBs, `data` components for prompts and RAG flows). Consumable by Dependency-Track and any CDX 1.6-aware tool.

## Connectors

- `scan`: local repository or directory scan
- `scan-github`: downloads a GitHub repository archive and scans it locally
- `scan-huggingface`: inspects Hugging Face model metadata
- `scan-aws`: inspects AWS inventory for Bedrock, Lambda, and S3 AI signals
- `scan-azure`: inspects Azure inventory for Azure OpenAI, Functions, and Storage AI signals
- `scan-gcp`: inspects GCP inventory for Vertex AI, Functions, and Storage AI signals

`scan-github` reads a token from `GITHUB_TOKEN` by default. Override with `--github-token-env` if needed.
`scan-huggingface` reads a token from `HUGGINGFACE_TOKEN` by default. Override with `--huggingface-token-env` if needed.
`scan-aws` uses `boto3` when available and respects `--aws-profile`.
`scan-azure` uses Azure SDK credentials when available.
`scan-gcp` uses Google Cloud SDK credentials when available.

## Policy

Policy files can be `TOML` or `JSON`. Current support:

- `approved_providers`
- `approved_models`
- `severity_overrides`

Example:

```toml
approved_providers = ["openai", "huggingface"]
approved_models = ["gpt-4o", "mistral-7b"]

[severity_overrides]
"prompt.pattern" = "low"
```

## Persistence

Saved scan history is stored in a local SQLite database at `~/.aibom/history.db` by default.

- `--save`: persist a scan after it runs
- `history`: list recent saved scans
- `show-scan`: render a saved scan in any supported output format
- `diff-scans`: compare two saved scans and show added or removed findings

Use `--db` to point at a different SQLite file.

## Tuning

Tuning files can be `TOML` or `JSON`. Current support:

- `exclude_patterns`
- `suppress_rule_ids`
- `path_suppressions`
- `severity_overrides`
- `confidence_overrides`
- `baseline_ignore_rule_ids`

Use tuning when you want to reduce noise without changing the broader policy model.

## Notes

- This version is static-analysis only.
- Findings are heuristic and include confidence levels.
- Large and binary files are skipped.
- Markdown, docs, tests, fixtures, and examples are excluded by default to reduce false positives.
- AWS, Azure, and GCP inventory scanning plus Hugging Face metadata scanning are implemented.
