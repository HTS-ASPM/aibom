from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
import hashlib
import json
from pathlib import Path
import re
import tomllib

from aibom.artifacts import scan_artifacts
from aibom.cache import (
    CacheStats,
    fingerprint_text,
    lookup as cache_lookup,
    store as cache_store,
)
from aibom.datasets import scan_datasets
from aibom.evidence import collect_github_actions, collect_mlflow_runs
from aibom.iac import scan_helm_k8s, scan_terraform
from aibom.models import Finding, MatchEvidence, ScanResult, ScanStats
from aibom.owasp_mapping import annotate_finding_metadata
from aibom.policy import apply_policy
from aibom.prompt_risk import scan_prompt_risks
from aibom.tuning import apply_tuning, merge_exclude_patterns


TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".swift",
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".sh",
    ".sql",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".idea",
    ".pytest_cache",
    ".mypy_cache",
}

DEFAULT_EXCLUDE_PATTERNS = [
    "*.md",
    "docs/*",
    "examples/*",
    "test*/*",
    "tests/*",
    "fixtures/*",
    ".git/*",
]

MANIFEST_PRIMARY_RULE_IDS = {
    "provider.openai.pattern",
    "provider.anthropic.pattern",
    "provider.google.pattern",
    "provider.azure_openai.pattern",
    "provider.bedrock.pattern",
    "provider.cohere_mistral.pattern",
    "package.ai_sdk.pattern",
    "framework.agent.pattern",
    "vector_db.pattern",
}


@dataclass(frozen=True, slots=True)
class DetectorRule:
    rule_id: str
    category: str
    name: str
    pattern: re.Pattern[str]
    severity: str
    confidence: str
    detector: str
    entity_type: str
    summary: str
    metadata: dict[str, str]


RULES = [
    DetectorRule(
        rule_id="provider.openai.pattern",
        category="provider",
        name="OpenAI usage",
        pattern=re.compile(r"\b(openai|gpt-4o|gpt-4\.1|text-embedding-3|chat\.completions)\b", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="provider-pattern",
        entity_type="provider",
        summary="Detected likely OpenAI API, SDK, or model usage.",
        metadata={"provider": "openai"},
    ),
    DetectorRule(
        rule_id="provider.anthropic.pattern",
        category="provider",
        name="Anthropic usage",
        pattern=re.compile(r"\b(anthropic|claude-3|claude-sonnet|claude-opus)\b", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="provider-pattern",
        entity_type="provider",
        summary="Detected likely Anthropic API, SDK, or model usage.",
        metadata={"provider": "anthropic"},
    ),
    DetectorRule(
        rule_id="provider.google.pattern",
        category="provider",
        name="Google model usage",
        pattern=re.compile(r"\b(gemini|vertexai|generativeai|palm)\b", re.IGNORECASE),
        severity="medium",
        confidence="medium",
        detector="provider-pattern",
        entity_type="provider",
        summary="Detected likely Google AI or Vertex AI usage.",
        metadata={"provider": "google"},
    ),
    DetectorRule(
        rule_id="provider.azure_openai.pattern",
        category="provider",
        name="Azure OpenAI usage",
        pattern=re.compile(r"\b(azure[_-]?openai|openai\.azure\.com|AzureOpenAI)\b", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="provider-pattern",
        entity_type="provider",
        summary="Detected likely Azure OpenAI usage.",
        metadata={"provider": "azure-openai"},
    ),
    DetectorRule(
        rule_id="provider.bedrock.pattern",
        category="provider",
        name="AWS Bedrock usage",
        pattern=re.compile(r"\b(bedrock|bedrock-runtime|amazon\.bedrock)\b", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="provider-pattern",
        entity_type="provider",
        summary="Detected likely AWS Bedrock usage.",
        metadata={"provider": "aws-bedrock"},
    ),
    DetectorRule(
        rule_id="provider.cohere_mistral.pattern",
        category="provider",
        name="Cohere or Mistral usage",
        pattern=re.compile(r"\b(cohere|command-r|mistral|mixtral)\b", re.IGNORECASE),
        severity="medium",
        confidence="medium",
        detector="provider-pattern",
        entity_type="provider",
        summary="Detected likely Cohere or Mistral usage.",
        metadata={"provider": "cohere-or-mistral"},
    ),
    DetectorRule(
        rule_id="package.ai_sdk.pattern",
        category="package",
        name="AI SDK or package reference",
        pattern=re.compile(r"\b(openai|anthropic|langchain|llamaindex|crewai|autogen|pinecone|weaviate|chromadb|faiss-cpu|sentence-transformers|transformers|boto3)\b", re.IGNORECASE),
        severity="low",
        confidence="medium",
        detector="package-pattern",
        entity_type="package",
        summary="Detected likely AI-related package or SDK reference.",
        metadata={},
    ),
    DetectorRule(
        rule_id="framework.agent.pattern",
        category="framework",
        name="Agent framework usage",
        pattern=re.compile(r"\b(langchain|langgraph|llamaindex|crewai|autogen|semantic[-_ ]kernel)\b", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="framework-pattern",
        entity_type="framework",
        summary="Detected likely AI orchestration or agent framework usage.",
        metadata={"framework_type": "agent"},
    ),
    DetectorRule(
        rule_id="vector_db.pattern",
        category="vector_db",
        name="Vector database usage",
        pattern=re.compile(r"\b(pinecone|weaviate|faiss|chroma(db)?|milvus|qdrant)\b", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="vector-db-pattern",
        entity_type="vector_db",
        summary="Detected likely vector database usage.",
        metadata={},
    ),
    DetectorRule(
        rule_id="model.identifier.pattern",
        category="model",
        name="Model identifier",
        pattern=re.compile(r"\b(gpt-4o|gpt-4\.1|gpt-4\.1-mini|claude-[\w.-]+|gemini-[\w.-]+|text-embedding-3-[\w-]+|mistral-[\w.-]+|mixtral-[\w.-]+)\b", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="model-pattern",
        entity_type="model",
        summary="Detected a likely LLM or embedding model identifier.",
        metadata={},
    ),
    DetectorRule(
        rule_id="embedding.pattern",
        category="embedding",
        name="Embedding model usage",
        pattern=re.compile(r"\b(embedding|embed_query|embed_documents|text-embedding|sentence-transformers)\b", re.IGNORECASE),
        severity="medium",
        confidence="medium",
        detector="embedding-pattern",
        entity_type="embedding",
        summary="Detected likely embedding model usage.",
        metadata={},
    ),
    DetectorRule(
        rule_id="rag.pattern",
        category="rag",
        name="RAG pipeline usage",
        pattern=re.compile(r"\b(retriever|retrievalqa|rag|similarity_search|vectorstore|rerank)\b", re.IGNORECASE),
        severity="medium",
        confidence="medium",
        detector="rag-pattern",
        entity_type="rag_component",
        summary="Detected likely retrieval-augmented generation pipeline components.",
        metadata={},
    ),
    DetectorRule(
        rule_id="env_var.ai.pattern",
        category="env_var",
        name="AI env var reference",
        pattern=re.compile(r"\b(OPENAI|ANTHROPIC|AZURE_OPENAI|BEDROCK|COHERE|MISTRAL|HUGGINGFACE|HF)_?[A-Z_]*\b"),
        severity="high",
        confidence="medium",
        detector="env-var-pattern",
        entity_type="env_var",
        summary="Detected environment variables related to AI providers or credentials.",
        metadata={},
    ),
    DetectorRule(
        rule_id="prompt.pattern",
        category="prompt",
        name="Prompt template or system prompt",
        pattern=re.compile(r"\b(system prompt|prompt template|messages\s*=|SystemMessage|HumanMessage|You are an?)\b", re.IGNORECASE),
        severity="medium",
        confidence="medium",
        detector="prompt-pattern",
        entity_type="prompt",
        summary="Detected likely prompt content or prompt-template construction.",
        metadata={},
    ),
    DetectorRule(
        rule_id="endpoint.ai.pattern",
        category="endpoint",
        name="External AI endpoint",
        pattern=re.compile(r"https://[^\s'\"]*(openai|anthropic|azure|bedrock|cohere|mistral|huggingface)[^\s'\"]*", re.IGNORECASE),
        severity="medium",
        confidence="high",
        detector="endpoint-pattern",
        entity_type="endpoint",
        summary="Detected a likely external AI API endpoint.",
        metadata={},
    ),
    DetectorRule(
        rule_id="secret.ai_key.pattern",
        category="secret",
        name="Possible hardcoded AI secret",
        pattern=re.compile(r"\b(sk-[A-Za-z0-9]{16,}|sk-ant-[A-Za-z0-9\-_]{16,}|hf_[A-Za-z0-9]{16,})\b"),
        severity="high",
        confidence="medium",
        detector="secret-pattern",
        entity_type="secret",
        summary="Detected a string that looks like a hardcoded AI provider token or API key.",
        metadata={"review_required": "true"},
    ),
]

DATA_PATTERNS = [
    re.compile(r"\b(customer|patient|invoice|payment|ssn|passport|dob|email|phone|address)\b", re.IGNORECASE),
    re.compile(r"\b(select\s+.+from|insert\s+into|update\s+\w+)\b", re.IGNORECASE),
]


def scan_path(
    root: Path,
    max_file_size: int = 512_000,
    exclude_patterns: list[str] | None = None,
    policy: dict | None = None,
    tuning: dict | None = None,
    cache_conn=None,
) -> ScanResult:
    """Scan a path. When ``cache_conn`` is provided, per-file findings are
    looked up by content sha256 + scanner version; misses are populated
    after running the per-file detectors. The tree-level layers (binary
    artifacts, IaC, CI evidence) are not cached — they're cheap."""
    stats = ScanStats()
    cache_stats = CacheStats()
    findings: list[Finding] = []
    exclude_patterns = merge_exclude_patterns(list(DEFAULT_EXCLUDE_PATTERNS) + (exclude_patterns or []), tuning or {})

    for path in iter_files(root, exclude_patterns):
        if not should_scan_file(path):
            stats.files_skipped += 1
            continue
        try:
            size = path.stat().st_size
        except OSError:
            stats.files_skipped += 1
            continue
        if size > max_file_size:
            stats.files_skipped += 1
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            stats.files_skipped += 1
            continue

        stats.files_scanned += 1
        stats.bytes_scanned += size
        rel_path = str(path.relative_to(root))
        per_file_findings: list[Finding] | None = None
        content_sha = fingerprint_text(text) if cache_conn is not None else None
        if cache_conn is not None and content_sha is not None:
            cached = cache_lookup(cache_conn, content_sha256=content_sha, rel_path=rel_path)
            if cached is not None:
                per_file_findings = cached
                cache_stats = CacheStats(
                    hits=cache_stats.hits + 1,
                    misses=cache_stats.misses,
                    inserted=cache_stats.inserted,
                )
        if per_file_findings is None:
            lines = text.splitlines()
            source_kind = classify_source_kind(rel_path)
            per_file_findings = []
            per_file_findings.extend(scan_parsed_dependencies(rel_path, path, text))
            per_file_findings.extend(scan_rules(rel_path, lines))
            per_file_findings.extend(scan_data_flow(rel_path, lines))
            per_file_findings.extend(scan_public_ai_endpoint(rel_path, lines))
            per_file_findings.extend(scan_datasets(rel_path, lines, source_kind))
            per_file_findings.extend(scan_prompt_risks(rel_path, lines, source_kind))
            if cache_conn is not None and content_sha is not None:
                cache_store(cache_conn, content_sha256=content_sha, rel_path=rel_path, findings=per_file_findings)
                cache_stats = CacheStats(
                    hits=cache_stats.hits,
                    misses=cache_stats.misses + 1,
                    inserted=cache_stats.inserted + 1,
                )
        findings.extend(per_file_findings)

    if root.exists():
        findings.extend(scan_artifacts(root))
        findings.extend(scan_terraform(root))
        findings.extend(scan_helm_k8s(root))
        findings.extend(collect_github_actions(root))
        findings.extend(collect_mlflow_runs(root))

    findings = demote_isolated_dataset_findings(findings)

    for finding in findings:
        annotate_finding_metadata(finding.rule_id, finding.metadata)

    findings = apply_tuning(dedupe_findings(findings), tuning or {})
    findings = apply_policy(findings, policy or {})
    return ScanResult(root=str(root), findings=findings, stats=stats)


def demote_isolated_dataset_findings(findings: list[Finding]) -> list[Finding]:
    """Demote `dataset.*` findings to `info` severity unless the same
    file (rel_path) also produced a `provider.*` finding.

    Dataset rules are noisy in isolation (one S3 URI in a doc snippet
    isn't worth medium severity), but become signal-bearing when the
    same file also touches a provider — e.g. a training script that
    pulls from S3 and calls OpenAI is a real data-flow risk. The
    original severity is preserved under ``metadata['original_severity']``
    for audit.
    """
    provider_paths = {
        finding.path
        for finding in findings
        if finding.category == "provider"
    }
    demoted: list[Finding] = []
    for finding in findings:
        if not finding.rule_id.startswith("dataset."):
            demoted.append(finding)
            continue
        if finding.path in provider_paths:
            demoted.append(finding)
            continue
        if finding.severity == "info":
            demoted.append(finding)
            continue
        new_metadata = dict(finding.metadata)
        new_metadata.setdefault("original_severity", finding.severity)
        demoted.append(
            Finding(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                category=finding.category,
                name=finding.name,
                severity="info",
                confidence=finding.confidence,
                path=finding.path,
                detector=finding.detector,
                entity_type=finding.entity_type,
                source_kind=finding.source_kind,
                summary=finding.summary,
                evidence=list(finding.evidence),
                metadata=new_metadata,
            )
        )
    return demoted


def iter_files(root: Path, exclude_patterns: list[str]):
    if root.is_file():
        if not is_excluded(root.name, exclude_patterns):
            yield root
        return
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            rel_path = str(path.relative_to(root))
            if is_excluded(rel_path, exclude_patterns):
                continue
            yield path


def should_scan_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name in {".env", "Dockerfile"}


def is_excluded(rel_path: str, patterns: list[str]) -> bool:
    return any(fnmatch(rel_path, pattern) for pattern in patterns)


def scan_rules(rel_path: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    source_kind = classify_source_kind(rel_path)
    for rule in RULES:
        if source_kind == "manifest" and rule.rule_id in MANIFEST_PRIMARY_RULE_IDS:
            continue
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
                    finding_id=build_finding_id(rel_path, rule.rule_id, [item.match for item in evidence]),
                    rule_id=rule.rule_id,
                    category=rule.category,
                    name=rule.name,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    path=rel_path,
                    detector=rule.detector,
                    entity_type=rule.entity_type,
                    source_kind=source_kind,
                    summary=rule.summary,
                    evidence=evidence,
                    metadata=dict(rule.metadata),
                )
            )
    return findings


def scan_data_flow(rel_path: str, lines: list[str]) -> list[Finding]:
    ai_line_hits: list[tuple[int, str]] = []
    data_line_hits: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, start=1):
        lowered = line.lower()
        if any(token in lowered for token in ("openai", "anthropic", "bedrock", "azureopenai", "gemini", "prompt")):
            ai_line_hits.append((line_number, line))
        if any(pattern.search(line) for pattern in DATA_PATTERNS):
            data_line_hits.append((line_number, line))

    if not ai_line_hits or not data_line_hits:
        return []

    first_ai = ai_line_hits[0]
    first_data = data_line_hits[0]
    return [
        Finding(
            finding_id=build_finding_id(rel_path, "data_flow.same_file", ["data-signal", "ai-signal"]),
            rule_id="data_flow.same_file",
            category="data_flow",
            name="Possible business data sent to AI flow",
            severity="high",
            confidence="low",
            path=rel_path,
            detector="data-flow-correlation",
            entity_type="data_flow",
            source_kind=classify_source_kind(rel_path),
            summary="Detected both likely business-data handling and AI usage in the same file. Review for sensitive data exposure.",
            evidence=[
                MatchEvidence(line=first_data[0], snippet=first_data[1][:220], match="data-signal"),
                MatchEvidence(line=first_ai[0], snippet=first_ai[1][:220], match="ai-signal"),
            ],
            metadata={"review_required": True},
        )
    ]


def scan_public_ai_endpoint(rel_path: str, lines: list[str]) -> list[Finding]:
    route_patterns = (
        re.compile(r"@app\.(get|post|put|delete|patch)\(", re.IGNORECASE),
        re.compile(r"router\.(get|post|put|delete|patch)\(", re.IGNORECASE),
        re.compile(r"app\.(get|post|put|delete|patch)\(", re.IGNORECASE),
        re.compile(r"Route\(", re.IGNORECASE),
    )
    ai_patterns = (
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\banthropic\b", re.IGNORECASE),
        re.compile(r"\bbedrock\b", re.IGNORECASE),
        re.compile(r"\bgemini\b", re.IGNORECASE),
        re.compile(r"chat\.completions", re.IGNORECASE),
    )

    route_hit: tuple[int, str] | None = None
    ai_hit: tuple[int, str] | None = None
    for line_number, line in enumerate(lines, start=1):
        if route_hit is None and any(pattern.search(line) for pattern in route_patterns):
            route_hit = (line_number, line)
        if ai_hit is None and any(pattern.search(line) for pattern in ai_patterns):
            ai_hit = (line_number, line)
        if route_hit and ai_hit:
            break

    if route_hit is None or ai_hit is None:
        return []

    return [
        Finding(
            finding_id=build_finding_id(rel_path, "endpoint.public_ai.same_file", ["route", "ai"]),
            rule_id="endpoint.public_ai.same_file",
            category="endpoint",
            name="Possible public AI endpoint",
            severity="high",
            confidence="low",
            path=rel_path,
            detector="endpoint-correlation",
            entity_type="endpoint",
            source_kind=classify_source_kind(rel_path),
            summary="Detected web route handling and AI usage in the same file. Review exposure, auth, and rate limits.",
            evidence=[
                MatchEvidence(line=route_hit[0], snippet=route_hit[1][:220], match="route"),
                MatchEvidence(line=ai_hit[0], snippet=ai_hit[1][:220], match="ai"),
            ],
            metadata={"review_required": True},
        )
    ]


def scan_parsed_dependencies(rel_path: str, path: Path, text: str) -> list[Finding]:
    parsers = {
        "requirements.txt": parse_requirements,
        "package.json": parse_package_json,
        "go.mod": parse_go_mod,
        "pyproject.toml": parse_pyproject,
    }
    parser = parsers.get(path.name)
    if parser is None:
        return []

    findings: list[Finding] = []
    for package_name in parser(text):
        metadata = classify_package(package_name)
        if not metadata:
            continue
        evidence_line = find_package_line(text, package_name)
        findings.append(
            Finding(
                finding_id=build_finding_id(rel_path, "package.manifest", [package_name]),
                rule_id="package.manifest",
                category=metadata["category"],
                name=metadata["name"],
                severity=metadata["severity"],
                confidence="high",
                path=rel_path,
                detector="manifest-parser",
                entity_type=metadata["entity_type"],
                source_kind="manifest",
                summary=metadata["summary"],
                evidence=[MatchEvidence(line=evidence_line[0], snippet=evidence_line[1], match=package_name)],
                metadata={"package": package_name, **metadata.get("metadata", {})},
            )
        )
    return findings


def parse_requirements(text: str) -> list[str]:
    packages: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        package = re.split(r"[<>=~\[]", line, maxsplit=1)[0].strip()
        if package:
            packages.append(package)
    return packages


def parse_package_json(text: str) -> list[str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    packages: list[str] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = payload.get(key, {})
        if isinstance(deps, dict):
            packages.extend(str(name) for name in deps.keys())
    return packages


def parse_go_mod(text: str) -> list[str]:
    packages: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("require "):
            rest = line.removeprefix("require ").strip()
            if rest.startswith("("):
                continue
            packages.append(rest.split()[0])
        elif line and not line.startswith(("//", "module ", "go ", "replace ", "exclude ", ")")):
            parts = line.split()
            if len(parts) >= 2 and "." in parts[0]:
                packages.append(parts[0])
    return packages


def parse_pyproject(text: str) -> list[str]:
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    packages: list[str] = []
    project = payload.get("project", {})
    packages.extend(extract_dependency_names(project.get("dependencies", [])))

    optional_deps = project.get("optional-dependencies", {})
    if isinstance(optional_deps, dict):
        for value in optional_deps.values():
            packages.extend(extract_dependency_names(value))

    poetry = payload.get("tool", {}).get("poetry", {})
    poetry_deps = poetry.get("dependencies", {})
    if isinstance(poetry_deps, dict):
        packages.extend(name for name in poetry_deps.keys() if name.lower() != "python")

    return packages


def extract_dependency_names(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    packages: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        package = re.split(r"[<>=~\[]", value, maxsplit=1)[0].strip()
        if package:
            packages.append(package)
    return packages


def classify_package(package_name: str) -> dict[str, str | dict[str, str]] | None:
    normalized = package_name.lower()
    mappings = {
        "openai": {
            "category": "provider",
            "name": "OpenAI dependency",
            "severity": "medium",
            "entity_type": "provider",
            "summary": "Manifest includes the OpenAI SDK.",
            "metadata": {"provider": "openai"},
        },
        "anthropic": {
            "category": "provider",
            "name": "Anthropic dependency",
            "severity": "medium",
            "entity_type": "provider",
            "summary": "Manifest includes the Anthropic SDK.",
            "metadata": {"provider": "anthropic"},
        },
        "google-generativeai": {
            "category": "provider",
            "name": "Google AI dependency",
            "severity": "medium",
            "entity_type": "provider",
            "summary": "Manifest includes a Google generative AI SDK.",
            "metadata": {"provider": "google"},
        },
        "langchain": {
            "category": "framework",
            "name": "LangChain dependency",
            "severity": "medium",
            "entity_type": "framework",
            "summary": "Manifest includes the LangChain framework.",
            "metadata": {"framework_type": "agent"},
        },
        "llamaindex": {
            "category": "framework",
            "name": "LlamaIndex dependency",
            "severity": "medium",
            "entity_type": "framework",
            "summary": "Manifest includes the LlamaIndex framework.",
            "metadata": {"framework_type": "agent"},
        },
        "crewai": {
            "category": "framework",
            "name": "CrewAI dependency",
            "severity": "medium",
            "entity_type": "framework",
            "summary": "Manifest includes the CrewAI framework.",
            "metadata": {"framework_type": "agent"},
        },
        "autogen": {
            "category": "framework",
            "name": "AutoGen dependency",
            "severity": "medium",
            "entity_type": "framework",
            "summary": "Manifest includes the AutoGen framework.",
            "metadata": {"framework_type": "agent"},
        },
        "pinecone": {
            "category": "vector_db",
            "name": "Pinecone dependency",
            "severity": "medium",
            "entity_type": "vector_db",
            "summary": "Manifest includes the Pinecone client.",
            "metadata": {},
        },
        "weaviate-client": {
            "category": "vector_db",
            "name": "Weaviate dependency",
            "severity": "medium",
            "entity_type": "vector_db",
            "summary": "Manifest includes the Weaviate client.",
            "metadata": {},
        },
        "chromadb": {
            "category": "vector_db",
            "name": "Chroma dependency",
            "severity": "medium",
            "entity_type": "vector_db",
            "summary": "Manifest includes the Chroma client.",
            "metadata": {},
        },
        "faiss-cpu": {
            "category": "vector_db",
            "name": "FAISS dependency",
            "severity": "medium",
            "entity_type": "vector_db",
            "summary": "Manifest includes the FAISS package.",
            "metadata": {},
        },
        "sentence-transformers": {
            "category": "embedding",
            "name": "Embedding dependency",
            "severity": "medium",
            "entity_type": "embedding",
            "summary": "Manifest includes embedding-related packages.",
            "metadata": {},
        },
        "transformers": {
            "category": "model",
            "name": "Transformers dependency",
            "severity": "low",
            "entity_type": "model",
            "summary": "Manifest includes the Transformers library.",
            "metadata": {},
        },
        "boto3": {
            "category": "provider",
            "name": "AWS SDK dependency",
            "severity": "low",
            "entity_type": "provider",
            "summary": "Manifest includes the AWS SDK, which may support Bedrock integration.",
            "metadata": {"provider": "aws"},
        },
    }
    return mappings.get(normalized)


def find_package_line(text: str, package_name: str) -> tuple[int, str]:
    for index, line in enumerate(text.splitlines(), start=1):
        if package_name in line:
            return index, line[:220]
    return 1, package_name


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.path, finding.rule_id, finding.category, finding.name)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return sorted(unique, key=lambda item: (item.path, item.category, item.name))


def build_finding_id(rel_path: str, rule_id: str, parts: list[str]) -> str:
    digest = hashlib.sha1("|".join([rel_path, rule_id, *parts]).encode("utf-8")).hexdigest()
    return digest[:16]


def classify_source_kind(rel_path: str) -> str:
    lowered = rel_path.lower()
    if any(part in lowered for part in ("test", "fixture", "example")):
        return "non_prod_code"
    if lowered.endswith(("requirements.txt", "package.json", "go.mod", "pyproject.toml")):
        return "manifest"
    if lowered.endswith((".json", ".yaml", ".yml", ".toml", ".env")):
        return "config"
    return "code"
