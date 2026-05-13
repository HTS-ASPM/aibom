from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
import shutil
import zipfile

from aibom.models import Finding, MatchEvidence, ScanResult, ScanStats
from aibom.policy import apply_policy
from aibom.remote import fetch_json
from aibom.scanner import scan_path
from aibom.scanner import build_finding_id


@dataclass(slots=True)
class GitHubRepoRef:
    owner: str
    repo: str
    ref: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_github_repo_ref(repo: str, ref: str) -> GitHubRepoRef:
    parts = repo.strip().split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("GitHub repo must be in the form owner/repo")
    return GitHubRepoRef(owner=parts[0], repo=parts[1], ref=ref)


def scan_github_repo(
    repo: str,
    ref: str = "main",
    token: str | None = None,
    max_file_size: int = 512_000,
    exclude_patterns: list[str] | None = None,
    policy: dict | None = None,
    tuning: dict | None = None,
    archive_fetcher=None,
) -> ScanResult:
    repo_ref = parse_github_repo_ref(repo, ref)
    fetcher = archive_fetcher or fetch_github_archive

    with TemporaryDirectory(prefix="aibom-github-") as temp_dir:
        temp_path = Path(temp_dir)
        archive_path = temp_path / f"{repo_ref.repo}-{repo_ref.ref}.zip"
        fetcher(repo_ref, archive_path, token)
        extracted_root = extract_github_archive(archive_path, temp_path / "repo")
        result = scan_path(
            extracted_root,
            max_file_size=max_file_size,
            exclude_patterns=exclude_patterns,
            policy=policy,
            tuning=tuning,
        )
        result.root = f"github://{repo_ref.slug}@{repo_ref.ref}"
        return result


def fetch_github_archive(repo_ref: GitHubRepoRef, destination: Path, token: str | None) -> None:
    url = f"https://api.github.com/repos/{repo_ref.owner}/{repo_ref.repo}/zipball/{repo_ref.ref}"
    from urllib.request import Request, urlopen

    request = Request(url, headers=build_github_headers(token))
    with urlopen(request) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)


def extract_github_archive(archive_path: Path, destination_dir: Path) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(destination_dir)

    children = [path for path in destination_dir.iterdir() if path.is_dir()]
    if not children:
        raise ValueError("Downloaded archive did not contain a repository directory")
    return children[0]


def build_github_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "aibom-scanner",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def scan_huggingface_model(
    model_id: str,
    token: str | None = None,
    metadata_fetcher=None,
    policy: dict | None = None,
) -> ScanResult:
    fetcher = metadata_fetcher or fetch_huggingface_model_metadata
    metadata = fetcher(model_id, token)
    findings = build_huggingface_findings(model_id, metadata)
    findings = apply_policy(findings, policy or {})
    return ScanResult(
        root=f"huggingface://{model_id}",
        findings=findings,
        stats=ScanStats(files_scanned=1, files_skipped=0, bytes_scanned=0),
    )


def fetch_huggingface_model_metadata(model_id: str, token: str | None) -> dict:
    headers = {"User-Agent": "aibom-scanner"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return fetch_json(f"https://huggingface.co/api/models/{model_id}", headers=headers)


def build_huggingface_findings(model_id: str, metadata: dict) -> list[Finding]:
    findings: list[Finding] = []
    tags = [str(tag) for tag in metadata.get("tags", [])]
    base_model = metadata.get("base_model") or metadata.get("cardData", {}).get("base_model")
    pipeline_tag = metadata.get("pipeline_tag")
    private = bool(metadata.get("private", False))

    findings.append(
        Finding(
            finding_id=build_finding_id(model_id, "hf.model.metadata", [model_id]),
            rule_id="hf.model.metadata",
            category="model",
            name="Hugging Face model",
            severity="medium",
            confidence="high",
            path=model_id,
            detector="huggingface-metadata",
            entity_type="model",
            source_kind="remote_metadata",
            summary="Detected a Hugging Face model record from remote metadata.",
            evidence=[MatchEvidence(line=1, snippet=model_id, match=model_id)],
            metadata={"private": private, "pipeline_tag": str(pipeline_tag or "")},
        )
    )

    if pipeline_tag:
        findings.append(
            Finding(
                finding_id=build_finding_id(model_id, "hf.pipeline_tag", [str(pipeline_tag)]),
                rule_id="hf.pipeline_tag",
                category="model",
                name="Hugging Face pipeline tag",
                severity="low",
                confidence="high",
                path=model_id,
                detector="huggingface-metadata",
                entity_type="model",
                source_kind="remote_metadata",
                summary="Detected the declared Hugging Face pipeline task for the model.",
                evidence=[MatchEvidence(line=1, snippet=str(pipeline_tag), match=str(pipeline_tag))],
                metadata={},
            )
        )

    if base_model:
        findings.append(
            Finding(
                finding_id=build_finding_id(model_id, "hf.base_model", [str(base_model)]),
                rule_id="hf.base_model",
                category="model",
                name="Hugging Face base model",
                severity="medium",
                confidence="medium",
                path=model_id,
                detector="huggingface-metadata",
                entity_type="model",
                source_kind="remote_metadata",
                summary="Detected a base model relationship in Hugging Face metadata.",
                evidence=[MatchEvidence(line=1, snippet=str(base_model), match=str(base_model))],
                metadata={},
            )
        )

    if any("text-generation" in tag or "llm" in tag for tag in tags):
        findings.append(
            Finding(
                finding_id=build_finding_id(model_id, "hf.genai.tag", tags),
                rule_id="hf.genai.tag",
                category="provider",
                name="Hugging Face generative model usage",
                severity="medium",
                confidence="medium",
                path=model_id,
                detector="huggingface-tag",
                entity_type="provider",
                source_kind="remote_metadata",
                summary="Detected generative AI related tags on the Hugging Face model.",
                evidence=[MatchEvidence(line=1, snippet=tag, match=tag) for tag in tags[:3]],
                metadata={"provider": "huggingface"},
            )
        )

    return findings


def scan_aws_account(
    account_label: str,
    region: str,
    profile: str | None = None,
    inventory_fetcher=None,
    policy: dict | None = None,
) -> ScanResult:
    fetcher = inventory_fetcher or fetch_aws_inventory
    inventory = fetcher(region=region, profile=profile)
    findings = build_aws_findings(account_label=account_label, region=region, inventory=inventory)
    findings = apply_policy(findings, policy or {})
    return ScanResult(
        root=f"aws://{account_label}/{region}",
        findings=findings,
        stats=ScanStats(files_scanned=0, files_skipped=0, bytes_scanned=0),
    )


def fetch_aws_inventory(region: str, profile: str | None) -> dict:
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise RuntimeError("AWS scanning requires boto3 to be installed or an injected inventory fetcher.") from exc

    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(**session_kwargs)

    inventory: dict[str, list[dict] | str] = {
        "bedrock_models": [],
        "lambdas": [],
        "buckets": [],
    }

    try:
        bedrock = session.client("bedrock", region_name=region)
        response = bedrock.list_foundation_models()
        inventory["bedrock_models"] = response.get("modelSummaries", [])
    except Exception:
        inventory["bedrock_models"] = []

    try:
        lambda_client = session.client("lambda", region_name=region)
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            inventory["lambdas"].extend(page.get("Functions", []))
    except Exception:
        inventory["lambdas"] = []

    try:
        s3_client = session.client("s3", region_name=region)
        response = s3_client.list_buckets()
        inventory["buckets"] = response.get("Buckets", [])
    except Exception:
        inventory["buckets"] = []

    return inventory


def build_aws_findings(account_label: str, region: str, inventory: dict) -> list[Finding]:
    findings: list[Finding] = []

    for model in inventory.get("bedrock_models", []):
        model_id = str(model.get("modelId", ""))
        provider_name = str(model.get("providerName", "aws-bedrock")).lower()
        if not model_id:
            continue
        findings.append(
            Finding(
                finding_id=build_finding_id(f"{account_label}:{region}", "aws.bedrock.model", [model_id]),
                rule_id="aws.bedrock.model",
                category="provider",
                name="AWS Bedrock model access",
                severity="medium",
                confidence="high",
                path=f"{account_label}/{region}/bedrock/{model_id}",
                detector="aws-inventory",
                entity_type="provider",
                source_kind="remote_metadata",
                summary="Detected an AWS Bedrock foundation model in account inventory.",
                evidence=[MatchEvidence(line=1, snippet=model_id, match=model_id)],
                metadata={"provider": provider_name, "region": region},
            )
        )

    for function in inventory.get("lambdas", []):
        function_name = str(function.get("FunctionName", ""))
        environment = function.get("Environment", {}).get("Variables", {}) or {}
        ai_keys = [key for key in environment.keys() if any(token in key for token in ("OPENAI", "ANTHROPIC", "BEDROCK", "HUGGINGFACE"))]

        if ai_keys:
            findings.append(
                Finding(
                    finding_id=build_finding_id(f"{account_label}:{region}", "aws.lambda.ai_env", [function_name, *sorted(ai_keys)]),
                    rule_id="aws.lambda.ai_env",
                    category="env_var",
                    name="AWS Lambda AI environment reference",
                    severity="high",
                    confidence="high",
                    path=f"{account_label}/{region}/lambda/{function_name}",
                    detector="aws-inventory",
                    entity_type="env_var",
                    source_kind="remote_metadata",
                    summary="Detected AI-related environment variable names in AWS Lambda configuration.",
                    evidence=[MatchEvidence(line=1, snippet=key, match=key) for key in sorted(ai_keys)[:3]],
                    metadata={"region": region, "function_name": function_name},
                )
            )

    for bucket in inventory.get("buckets", []):
        bucket_name = str(bucket.get("Name", ""))
        lowered = bucket_name.lower()
        if any(token in lowered for token in ("vector", "embedding", "rag", "prompt")):
            findings.append(
                Finding(
                    finding_id=build_finding_id(f"{account_label}:{region}", "aws.s3.ai_bucket", [bucket_name]),
                    rule_id="aws.s3.ai_bucket",
                    category="rag",
                    name="AWS S3 AI data bucket",
                    severity="medium",
                    confidence="low",
                    path=f"{account_label}/{region}/s3/{bucket_name}",
                    detector="aws-inventory",
                    entity_type="rag_component",
                    source_kind="remote_metadata",
                    summary="Detected an S3 bucket name that suggests AI, RAG, or embedding data usage.",
                    evidence=[MatchEvidence(line=1, snippet=bucket_name, match=bucket_name)],
                    metadata={"region": region},
                )
            )

    return findings


def scan_azure_subscription(
    subscription_label: str,
    subscription_id: str,
    inventory_fetcher=None,
    policy: dict | None = None,
) -> ScanResult:
    fetcher = inventory_fetcher or fetch_azure_inventory
    inventory = fetcher(subscription_id=subscription_id)
    findings = build_azure_findings(subscription_label=subscription_label, subscription_id=subscription_id, inventory=inventory)
    findings = apply_policy(findings, policy or {})
    return ScanResult(
        root=f"azure://{subscription_label}/{subscription_id}",
        findings=findings,
        stats=ScanStats(files_scanned=0, files_skipped=0, bytes_scanned=0),
    )


def fetch_azure_inventory(subscription_id: str) -> dict:
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.mgmt.resource import ResourceManagementClient  # type: ignore
        from azure.mgmt.storage import StorageManagementClient  # type: ignore
        from azure.mgmt.web import WebSiteManagementClient  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Azure scanning requires azure SDK packages or an injected inventory fetcher."
        ) from exc

    credential = DefaultAzureCredential()
    resource_client = ResourceManagementClient(credential, subscription_id)
    storage_client = StorageManagementClient(credential, subscription_id)
    web_client = WebSiteManagementClient(credential, subscription_id)

    inventory: dict[str, list[dict]] = {
        "azure_openai_accounts": [],
        "function_apps": [],
        "storage_accounts": [],
    }

    try:
        for resource in resource_client.resources.list(filter="resourceType eq 'Microsoft.CognitiveServices/accounts'"):
            kind = str(getattr(resource, "kind", "") or "")
            if "openai" in kind.lower():
                inventory["azure_openai_accounts"].append(
                    {
                        "name": resource.name,
                        "location": getattr(resource, "location", ""),
                        "kind": kind,
                    }
                )
    except Exception:
        inventory["azure_openai_accounts"] = []

    try:
        for site in web_client.web_apps.list():
            kind = str(getattr(site, "kind", "") or "")
            if "functionapp" in kind.lower():
                settings = {}
                try:
                    config = web_client.web_apps.list_application_settings(
                        resource_group_name=extract_resource_group(site.id),
                        name=site.name,
                    )
                    settings = getattr(config, "properties", {}) or {}
                except Exception:
                    settings = {}
                inventory["function_apps"].append(
                    {
                        "name": site.name,
                        "location": getattr(site, "location", ""),
                        "settings": settings,
                    }
                )
    except Exception:
        inventory["function_apps"] = []

    try:
        for account in storage_client.storage_accounts.list():
            inventory["storage_accounts"].append(
                {
                    "name": account.name,
                    "location": getattr(account, "location", ""),
                }
            )
    except Exception:
        inventory["storage_accounts"] = []

    return inventory


def build_azure_findings(subscription_label: str, subscription_id: str, inventory: dict) -> list[Finding]:
    findings: list[Finding] = []

    for account in inventory.get("azure_openai_accounts", []):
        account_name = str(account.get("name", ""))
        if not account_name:
            continue
        findings.append(
            Finding(
                finding_id=build_finding_id(subscription_id, "azure.openai.account", [account_name]),
                rule_id="azure.openai.account",
                category="provider",
                name="Azure OpenAI account",
                severity="medium",
                confidence="high",
                path=f"{subscription_label}/{subscription_id}/openai/{account_name}",
                detector="azure-inventory",
                entity_type="provider",
                source_kind="remote_metadata",
                summary="Detected an Azure OpenAI account in subscription inventory.",
                evidence=[MatchEvidence(line=1, snippet=account_name, match=account_name)],
                metadata={"provider": "azure-openai", "location": str(account.get("location", ""))},
            )
        )

    for app in inventory.get("function_apps", []):
        app_name = str(app.get("name", ""))
        settings = app.get("settings", {}) or {}
        ai_keys = [key for key in settings.keys() if any(token in key for token in ("OPENAI", "ANTHROPIC", "AZURE_OPENAI", "HUGGINGFACE", "BEDROCK"))]
        if ai_keys:
            findings.append(
                Finding(
                    finding_id=build_finding_id(subscription_id, "azure.function.ai_env", [app_name, *sorted(ai_keys)]),
                    rule_id="azure.function.ai_env",
                    category="env_var",
                    name="Azure Function AI environment reference",
                    severity="high",
                    confidence="high",
                    path=f"{subscription_label}/{subscription_id}/function/{app_name}",
                    detector="azure-inventory",
                    entity_type="env_var",
                    source_kind="remote_metadata",
                    summary="Detected AI-related application settings in Azure Function configuration.",
                    evidence=[MatchEvidence(line=1, snippet=key, match=key) for key in sorted(ai_keys)[:3]],
                    metadata={"location": str(app.get("location", "")), "function_name": app_name},
                )
            )

    for storage in inventory.get("storage_accounts", []):
        account_name = str(storage.get("name", ""))
        lowered = account_name.lower()
        if any(token in lowered for token in ("vector", "embedding", "rag", "prompt")):
            findings.append(
                Finding(
                    finding_id=build_finding_id(subscription_id, "azure.storage.ai_signal", [account_name]),
                    rule_id="azure.storage.ai_signal",
                    category="rag",
                    name="Azure Storage AI data account",
                    severity="medium",
                    confidence="low",
                    path=f"{subscription_label}/{subscription_id}/storage/{account_name}",
                    detector="azure-inventory",
                    entity_type="rag_component",
                    source_kind="remote_metadata",
                    summary="Detected a storage account name that suggests AI, RAG, or embedding data usage.",
                    evidence=[MatchEvidence(line=1, snippet=account_name, match=account_name)],
                    metadata={"location": str(storage.get("location", ""))},
                )
            )

    return findings


def extract_resource_group(resource_id: str | None) -> str:
    if not resource_id:
        return ""
    parts = str(resource_id).split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""


def scan_gcp_project(
    project_label: str,
    project_id: str,
    inventory_fetcher=None,
    policy: dict | None = None,
) -> ScanResult:
    fetcher = inventory_fetcher or fetch_gcp_inventory
    inventory = fetcher(project_id=project_id)
    findings = build_gcp_findings(project_label=project_label, project_id=project_id, inventory=inventory)
    findings = apply_policy(findings, policy or {})
    return ScanResult(
        root=f"gcp://{project_label}/{project_id}",
        findings=findings,
        stats=ScanStats(files_scanned=0, files_skipped=0, bytes_scanned=0),
    )


def fetch_gcp_inventory(project_id: str) -> dict:
    try:
        from google.cloud import aiplatform_v1  # type: ignore
        from google.cloud import functions_v2  # type: ignore
        from google.cloud import storage  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "GCP scanning requires google-cloud SDK packages or an injected inventory fetcher."
        ) from exc

    inventory: dict[str, list[dict]] = {
        "vertex_endpoints": [],
        "functions": [],
        "buckets": [],
    }

    try:
        endpoint_client = aiplatform_v1.EndpointServiceClient()
        parent = f"projects/{project_id}/locations/us-central1"
        for endpoint in endpoint_client.list_endpoints(parent=parent):
            inventory["vertex_endpoints"].append(
                {
                    "name": getattr(endpoint, "name", ""),
                    "display_name": getattr(endpoint, "display_name", ""),
                }
            )
    except Exception:
        inventory["vertex_endpoints"] = []

    try:
        functions_client = functions_v2.FunctionServiceClient()
        parent = f"projects/{project_id}/locations/-"
        for fn in functions_client.list_functions(parent=parent):
            service_config = getattr(fn, "service_config", None)
            env_vars = getattr(service_config, "environment_variables", {}) if service_config else {}
            inventory["functions"].append(
                {
                    "name": getattr(fn, "name", ""),
                    "environment_variables": dict(env_vars or {}),
                }
            )
    except Exception:
        inventory["functions"] = []

    try:
        storage_client = storage.Client(project=project_id)
        for bucket in storage_client.list_buckets():
            inventory["buckets"].append({"name": bucket.name, "location": getattr(bucket, "location", "")})
    except Exception:
        inventory["buckets"] = []

    return inventory


def build_gcp_findings(project_label: str, project_id: str, inventory: dict) -> list[Finding]:
    findings: list[Finding] = []

    for endpoint in inventory.get("vertex_endpoints", []):
        endpoint_name = str(endpoint.get("display_name") or endpoint.get("name") or "")
        if not endpoint_name:
            continue
        findings.append(
            Finding(
                finding_id=build_finding_id(project_id, "gcp.vertex.endpoint", [endpoint_name]),
                rule_id="gcp.vertex.endpoint",
                category="provider",
                name="GCP Vertex AI endpoint",
                severity="medium",
                confidence="high",
                path=f"{project_label}/{project_id}/vertex/{endpoint_name}",
                detector="gcp-inventory",
                entity_type="provider",
                source_kind="remote_metadata",
                summary="Detected a Vertex AI endpoint in project inventory.",
                evidence=[MatchEvidence(line=1, snippet=endpoint_name, match=endpoint_name)],
                metadata={"provider": "google", "project_id": project_id},
            )
        )

    for function in inventory.get("functions", []):
        function_name = str(function.get("name", ""))
        env_vars = function.get("environment_variables", {}) or {}
        ai_keys = [key for key in env_vars.keys() if any(token in key for token in ("OPENAI", "ANTHROPIC", "VERTEX", "GOOGLE_API", "HUGGINGFACE"))]
        if ai_keys:
            findings.append(
                Finding(
                    finding_id=build_finding_id(project_id, "gcp.function.ai_env", [function_name, *sorted(ai_keys)]),
                    rule_id="gcp.function.ai_env",
                    category="env_var",
                    name="GCP Function AI environment reference",
                    severity="high",
                    confidence="high",
                    path=f"{project_label}/{project_id}/function/{function_name}",
                    detector="gcp-inventory",
                    entity_type="env_var",
                    source_kind="remote_metadata",
                    summary="Detected AI-related environment variable names in GCP Function configuration.",
                    evidence=[MatchEvidence(line=1, snippet=key, match=key) for key in sorted(ai_keys)[:3]],
                    metadata={"project_id": project_id, "function_name": function_name},
                )
            )

    for bucket in inventory.get("buckets", []):
        bucket_name = str(bucket.get("name", ""))
        lowered = bucket_name.lower()
        if any(token in lowered for token in ("vector", "embedding", "rag", "prompt")):
            findings.append(
                Finding(
                    finding_id=build_finding_id(project_id, "gcp.storage.ai_bucket", [bucket_name]),
                    rule_id="gcp.storage.ai_bucket",
                    category="rag",
                    name="GCP Storage AI data bucket",
                    severity="medium",
                    confidence="low",
                    path=f"{project_label}/{project_id}/storage/{bucket_name}",
                    detector="gcp-inventory",
                    entity_type="rag_component",
                    source_kind="remote_metadata",
                    summary="Detected a GCS bucket name that suggests AI, RAG, or embedding data usage.",
                    evidence=[MatchEvidence(line=1, snippet=bucket_name, match=bucket_name)],
                    metadata={"project_id": project_id, "location": str(bucket.get("location", ""))},
                )
            )

    return findings
