# HTS-ASPM ↔ AiBOM ingest protocol

> Schema version: **1.0**
> Wire content-type: `application/vnd.aibom+json`
> Schema header: `X-Aibom-Schema-Version: 1.0`
> Producer: `aibom` (this repo) — see `aibom.hts_aspm.payload`
> Consumer: HTS-ASPM (sibling product, private repo)

This document is the integration contract between AiBOM and the HTS-ASPM
ASPM product. AiBOM produces the envelope described here; HTS-ASPM
implements the ingest endpoint described in [Endpoint contract](#endpoint-contract)
below.

The canonical, code-level definition of the request body lives in
`src/aibom/hts_aspm/payload.py` — the docstring there is normative and
should be considered the source of truth if this doc drifts.

---

## Endpoint contract

```
POST   <hts-aspm-ingest-url>
Authorization:           Bearer <token>          (optional but expected in prod)
Content-Type:            application/vnd.aibom+json
X-Aibom-Schema-Version:  1.0
X-Aibom-Scan-Id:         urn:uuid:<uuid>
X-Aibom-Project:         <opaque project identifier>   (optional)
```

The request body is the JSON document built by
`aibom.hts_aspm.build_aspm_payload(...)`. Bytes are the *canonical*
encoding — sorted keys, ASCII-escaped, no insignificant whitespace —
so two scans of identical content produce byte-identical requests.

### Expected response (minimum)

```
HTTP/1.1 200 OK
Content-Type: application/json

{ "ingested": true, "asset_count": 42 }
```

Receivers MAY return additional fields (e.g. `dedup_id`, `accepted_at`,
`warnings[]`). AiBOM's CLI surfaces `status` + `scan_id` in its stdout
summary; the rest is ignored by the producer.

Error responses use standard 4xx / 5xx semantics. AiBOM raises
`aibom.aspm_push.PushError` on any non-2xx status; the CLI exits
non-zero (exit code 4).

---

## Idempotency

`scan_id` is the idempotency key.

* AiBOM generates `scan_id` as `urn:uuid:<uuid5(scan_root + scanned_at)>`.
* `scanned_at` is captured once per `build_aspm_payload` invocation and
  formatted as `YYYY-MM-DDTHH:MM:SSZ` (ISO 8601, UTC).
* The payload bytes are deterministic for a given `(scan_root,
  scanned_at, scan content)` triple.
* HTS-ASPM SHOULD treat `scan_id` as a unique key in its ingest table
  and ignore duplicates (or upsert idempotently). Retries with the same
  `scan_id` must not double-count assets or findings.

If a caller intentionally re-ingests the *same* scan with a *different*
timestamp (e.g. a backfill), they get a different `scan_id` and HTS-ASPM
will treat it as a new record. That's the intended behavior — operators
can suppress at the receiver layer if needed.

---

## Recommended HTS-ASPM-side processing

1. **Persist `bom` verbatim** as the authoritative source of truth.
   Don't re-derive it from `asset_graph` or `findings_summary` — those
   are denormalized views for query performance, not sources of truth.
2. **Index `bom.components[]` and `bom.services[]`** into the existing
   ASPM asset graph. The `bom-ref` of each entry is stable across runs
   for the same logical asset (deterministic UUID5).
3. **Link `top_findings[]` and `kev_matches[]`** to existing component
   records via `metadata.bom_ref` or `path`. Findings without a matching
   asset should attach to the root application component.
4. **Render `findings_summary.by_framework`** in dashboards directly —
   it's already keyed by the framework reference id (e.g.
   `LLM01-prompt-injection`), no parsing needed.
5. **Use `risk_scores[].score`** as the primary asset-level risk axis.
   `components` carries the per-component breakdown (e.g.
   `["base_severity", 30]`) so the UI can explain *why*.
6. **Verify `signature_manifest.sha256`** (when present) against the
   canonical bytes of the inlined `bom` field before ingest if you're
   running in a high-assurance configuration. The `cosign_command` field
   is informational — the receiver does not invoke it.

---

## Versioning policy

`schema_version` follows simple major versioning:

* **Additive, backwards-compatible** changes — new top-level keys, new
  nested keys, new framework references — keep the same major. Existing
  HTS-ASPM consumers MUST tolerate unknown keys.
* **Breaking** changes — removing keys, renaming keys, changing
  semantics of existing keys, restructuring nesting — bump the major
  (1.0 → 2.0). The wire header `X-Aibom-Schema-Version` mirrors the
  constant so receivers can route on it (e.g. dispatch to a v1 vs v2
  ingest handler).

Producers SHOULD continue emitting the highest version they support;
receivers SHOULD reject schema versions they do not implement with a
clear 4xx response.

---

## Example payload (trimmed)

```jsonc
{
  "schema_version": "1.0",
  "scanner": { "name": "aibom", "version": "0.2.0" },
  "scan_root": "/repos/acme/llm-app",
  "scan_id": "urn:uuid:0e8b86d0-8d9f-50d1-9c46-9e30aebcb01a",
  "scanned_at": "2026-05-20T11:22:33Z",

  "bom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:7d8...",
    "version": 1,
    "metadata": { /* ...timestamp, tools, component, properties... */ },
    "components": [ /* ML models, libraries, datasets, prompts... */ ],
    "services":   [ /* providers (OpenAI/Anthropic/...), vector DBs, endpoints */ ],
    "dependencies": [ /* root depends_on -> components/services */ ]
  },

  "asset_graph": {
    // Smaller, dashboard-friendly view. include_findings=False here —
    // the receiver can pull individual findings from top_findings[].
    "nodes": [
      { "id": "asset:application:root", "type": "application", "label": "/repos/acme/llm-app", "properties": {} },
      { "id": "asset:provider::openai", "type": "provider",    "label": "openai",  "properties": { "max_severity": "high", "occurrences": 3, "risk_score": 45 } }
    ],
    "edges": [
      { "source": "asset:application:root", "target": "asset:provider::openai", "kind": "depends_on" }
    ]
  },

  "findings_summary": {
    "by_severity":  { "critical": 0, "high": 2, "medium": 5, "low": 1, "info": 0 },
    "by_category":  { "provider": 3, "model": 2, "prompt_risk": 3 },
    "by_framework": {
      "owasp_llm":   { "LLM01-prompt-injection": 1, "LLM05-supply-chain": 3 },
      "mitre_atlas": { "AML.T0010-ML-Supply-Chain-Compromise": 3 },
      "nist_ai_rmf": { "GV-1.3": 3, "MS-2.10": 1 }
    },
    "total": 8
  },

  "top_findings": [
    {
      "finding_id": "prompt_risk:jailbreak:src/agents/router.py:42",
      "rule_id":    "prompt_risk.jailbreak",
      "category":   "prompt_risk",
      "name":       "jailbreak phrasing in prompt",
      "severity":   "high",
      "confidence": "high",
      "path":       "src/agents/router.py",
      // ...evidence, metadata.owasp_llm, etc.
    }
    // up to 50 entries, sorted (severity desc, risk_score desc, finding_id asc)
  ],

  "risk_scores": [
    {
      "asset_key":  "provider::openai",
      "score":      45,
      "components": [["base_severity", 20], ["additional:provider.openai.pattern", 10], ["framework_boost", 15]],
      "contributing_finding_ids": ["provider:openai:src/llm.py:12", "..."]
    }
  ],

  "vex":         [ /* CycloneDX 1.6 vulnerabilities[] entries from AiBOM VEX feed, may be [] */ ],
  "kev_matches": [ /* KEV-cross-referenced Finding dicts, [] when no KEV feed is loaded */ ],

  // Optional — present only when build_aspm_payload(..., signer=...) is used
  "signature_manifest": {
    "artifact_path":   "inline:bom.json",
    "sha256":          "9f6...",
    "intended_signer": "ci@hts.consulting",
    "rekor_log_url":   "https://rekor.sigstore.dev",
    "cosign_command":  "cosign sign-blob --yes --key env://COSIGN_KEY --output-signature bom.json.sig --output-certificate bom.json.cert bom.json"
  }
}
```

---

## CLI usage

```
aibom push <target> \
    --aspm-url https://aspm.example.com/aibom/ingest \
    --project acme/llm-app \
    --token-env ASPM_TOKEN \
    [--kev-feed /var/lib/aibom/kev.json] \
    [--no-vex] [--no-kev] \
    [--signer ci@hts.consulting] [--key-ref env://COSIGN_KEY]
```

On success the CLI prints a JSON summary to stdout:

```json
{
  "posted": true,
  "status": 200,
  "scan_id": "urn:uuid:0e8b86d0-8d9f-50d1-9c46-9e30aebcb01a",
  "schema_version": "1.0",
  "findings_total": 8
}
```

Exit codes:

| code | meaning                                  |
| ---- | ---------------------------------------- |
| 0    | success                                  |
| 2    | target path does not exist               |
| 4    | push failed (network / non-2xx response) |
