# AiBOM

AiBOM is an open-source **AI Bill of Materials** scanner. Point it at a repo, a
GitHub / GitLab / Bitbucket / Gitea project, a cloud account, or a Hugging Face
model and it returns a CycloneDX 1.6 ML-BOM, a SARIF report, EU AI Act
Annex IV / NIST AI RMF / ISO 42001 HTML compliance evidence, and an asset
graph — entirely from the stdlib, no runtime dependencies, no SaaS callback.

> Status: **Beta (v0.2.0)** — production-ready for static + IaC + CI-evidence
> AI inventory. Supports Python 3.11 – 3.14.

## Why AiBOM

Regulators (EU AI Act Annex IV, NIST AI RMF, ISO 42001) and security teams
(OWASP LLM Top-10 2025, OWASP MCP Top-10, MITRE ATLAS) now require the same
discipline for AI systems that SBOM tooling delivers for traditional
software: a verifiable inventory of every model, dataset, provider, vector
store, prompt, and training run a codebase touches, plus a way to detect
drift and signed provenance.

AiBOM scans the artefacts where that evidence actually lives — source code,
manifests, Terraform / Helm / K8s, GitHub Actions workflows, MLflow run
folders, and Hugging Face metadata — and emits CycloneDX 1.6 with the
`modelCard`, `formulation`, and `evidence` fields the standards call for.

## Install

```bash
pip install aibom
```

Or run from source (no install needed, stdlib only):

```bash
PYTHONPATH=src python -m aibom scan .
```

Requires Python 3.11+ (uses `tomllib`).

## Quickstart

```bash
# Scan the current directory and print findings as JSON
python -m aibom scan .

# Try the bundled demo fixture (no setup required)
python -m aibom demo --format markdown

# CycloneDX 1.6 ML-BOM ready for Dependency-Track / OWASP
python -m aibom scan . --format cyclonedx --output bom.cdx.json

# Full Annex IV evidence pack
python -m aibom report --type annex-iv . --output annex-iv.html
```

## CLI overview — 22 subcommands

### Scan

| Command | Purpose |
| --- | --- |
| `scan` | Scan a local path |
| `scan-github` | Download a GitHub repo archive (PAT or GitHub App token) |
| `scan-gitlab` | GitLab archive (project id or url-encoded path), self-hosted supported |
| `scan-bitbucket` | Bitbucket Cloud / Server / DC archive |
| `scan-huggingface` | Inspect Hugging Face model metadata |
| `scan-aws` / `scan-azure` / `scan-gcp` | Cloud inventory (Bedrock, AOAI, Vertex, Lambda/Functions, S3/Blob/GCS) |
| `scan-refs` | Scan only files changed between two git refs (PR-scoped) |

### Diff & history

| Command | Purpose |
| --- | --- |
| `history` | List saved scans (local SQLite) |
| `show-scan` | Re-render a saved scan in any format |
| `diff-scans` | DB-backed diff of two saved scans |
| `scan-diff` | File-backed diff (no DB required) — JSON or HTML |

### Reports

| Command | Purpose |
| --- | --- |
| `report --type annex-iv` | EU AI Act Annex IV evidence (self-contained HTML) |
| `report --type nist-rmf` | NIST AI RMF 1.0 mapping |
| `report --type iso-42001` | ISO/IEC 42001:2023 AIMS evidence |
| `dashboard` | Executive HTML dashboard (risk score, providers, top findings) |
| `asset-graph` | JSON asset graph for visualisation |
| `asset-graph-diff` | Drift between two asset graphs |
| `unified-bom` | Merge AiBOM with an external CycloneDX SBOM (Syft / Trivy / cdxgen / HTS-ASPM SBOM) |

### VEX / KEV / signing

| Command | Purpose |
| --- | --- |
| `vex` | Cross-reference a BOM against the AiBOM VEX/VDR feed |
| `kev` | Cross-reference against the CISA Known Exploited Vulnerabilities catalog |
| `sign-bom` | Build a Sigstore / cosign-friendly signing manifest |

### Push & PR integration

| Command | Purpose |
| --- | --- |
| `pr-comment github\|gitlab\|bitbucket-server\|gitea` | Post a scan or diff summary as a PR / MR comment |
| `check-run` | Post a GitHub Check Run from a scan result |
| `webhook` | Stdlib HTTP receiver — auto-scan on push / PR events (GitHub / GitLab / Gitea) |

### Cache & demo

| Command | Purpose |
| --- | --- |
| `cache stats\|clear\|prune` | Manage the per-file fingerprint cache used by `--use-cache` |
| `demo` | Scan a built-in tiny fixture — useful for kicking the tyres |

`python -m aibom <cmd> --help` for the full surface.

## Output formats

- **`json`** — machine-readable findings + summary stats
- **`markdown`** — human-readable report (PR-comment friendly)
- **`sarif`** — SARIF 2.1.0, consumable by GitHub code-scanning, Defect Dojo, etc.
- **`cyclonedx`** — **CycloneDX 1.6 ML-BOM** with `machine-learning-model`
  components carrying `modelCard`, `service` components for providers and
  vector DBs, `data` components for datasets / prompts / RAG flows, and
  `formulation` blocks populated from CI workflows and MLflow runs
- **HTML compliance** — fully self-contained (inline CSS, no JS / fonts /
  external assets) so the output renders in air-gapped environments and is
  safe to attach to an audit dossier

## Standards covered

| Standard | What AiBOM emits |
| --- | --- |
| OWASP LLM Top-10 (2025) | `metadata.owasp_llm` per finding |
| OWASP MCP Top-10 | `metadata.owasp_mcp` for MCP-related findings |
| MITRE ATLAS | `metadata.mitre_atlas` |
| NIST AI RMF 1.0 | `metadata.nist_ai_rmf` + `report --type nist-rmf` |
| ISO/IEC 42001:2023 | `report --type iso-42001` |
| EU AI Act Annex IV | `report --type annex-iv` |
| CISA KEV catalog | `kev` subcommand |
| Sigstore / cosign | `sign-bom` subcommand |
| CycloneDX 1.6 ML-BOM | `--format cyclonedx` |

## Integrations

- **Source hosts** — GitHub (PAT + GitHub App installation token), GitLab,
  Bitbucket Cloud + Server / DC, Gitea. All connectors stream the
  repo-archive tarball over HTTPS, scan in a temp dir, then discard — no
  clone needed and no secrets are persisted.
- **CI evidence** — GitHub Actions workflows are parsed for GPU runners,
  training entrypoints (`accelerate launch`, `torchrun`, `deepspeed`,
  `python train.py`), model registry pushes, and dataset uploads.
- **MLflow** — on-disk `mlruns/` layout is inspected without requiring the
  `mlflow` package or a tracking-server connection.
- **IaC** — Terraform parser flags AI/ML resources (Bedrock, Cognitive,
  Vertex, Pinecone, etc.) and Helm/K8s parser flags AI serving images
  (vLLM, TGI, Triton, Ollama, LangServe, LiteLLM, Qdrant, Weaviate, …).
- **PR comments + GitHub Check Runs** — post a scan or diff summary into a
  PR / MR with `pr-comment` or as a Check Run with `check-run`.
- **Webhook receiver** — `aibom webhook` runs a stdlib HTTP server that
  auto-scans on push / PR / MR events from GitHub / GitLab / Gitea with HMAC
  signature verification.
- **VS Code** — the bundled extension under `src/aibom/vscode/` lights up
  finding squiggles in the editor.

## Configuration

### Policy (TOML or JSON)

```toml
approved_providers = ["openai", "huggingface"]
approved_models    = ["gpt-4o", "claude-3-5-sonnet-20241022"]

[severity_overrides]
"prompt.pattern" = "low"
```

### Tuning (TOML or JSON)

- `exclude_patterns`, `suppress_rule_ids`, `path_suppressions`
- `severity_overrides`, `confidence_overrides`, `baseline_ignore_rule_ids`

Use tuning to silence false positives without touching the policy model.

### Persistence

Saved scans live in a local SQLite database at `~/.aibom/history.db` (override
with `--db`). The fingerprint cache for `--use-cache` lives in a separate
SQLite file (`cache stats|clear|prune` to manage it).

## Where AiBOM fits

AiBOM is intentionally a **scanner library + CLI**, not a SaaS. It overlaps
with:

- **OWASP AIBOM Generator** — AiBOM has broader detection (IaC + CI + MLflow
  + cloud inventory + Hugging Face) and ships compliance HTML out of the box.
- **Snyk AI-BOM, Cycode AI-SPM, Mend AI** — those are paid SaaS suites with
  runtime correlation and policy UIs; AiBOM is the OSS, self-hosted,
  no-callback alternative aimed at audit-evidence + CI gating.
- **CycloneDX tooling (Syft / Trivy / cdxgen)** — AiBOM consumes their
  output via `unified-bom` so an existing SBOM pipeline keeps working and
  you only need AiBOM for the AI-specific layer.

## What's NOT here (honest gap list)

- **No live runtime correlation** — AiBOM is static analysis + IaC parsing
  + cloud inventory. It does not hook into running inference traffic, eBPF
  probes, or model gateways. Pair with LiteLLM logs / OpenLLMetry for that.
- **No SaaS UI** — there is an executive HTML dashboard, but no multi-tenant
  web app. Bring your own dashboard (Dependency-Track, Grafana on the
  asset-graph JSON, etc.).
- **No prompt-injection runtime defence** — `prompt.pattern` flags risky
  prompt construction but does not act as a guardrail at inference time.
- **No proprietary model registry support** — only Hugging Face, MLflow,
  and the cloud-native registries (Bedrock, AOAI, Vertex, SageMaker) ship
  detectors today.

## Development

```bash
# Run the full test suite (no install required)
PYTHONPATH=src python -m unittest discover -s tests
```

CI runs on Python 3.11 – 3.14 against `ubuntu-latest`.

## License

Apache-2.0. See [LICENSE](LICENSE).
