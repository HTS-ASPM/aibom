"""OpenTelemetry GenAI semconv reconciler.

Consumes a JSON file (or list) of OTel spans that follow the GenAI
semantic-conventions spec, aggregates per (system, model) pairs, and
diffs against the static BOM's `machine-learning-model` components.

GenAI semconv attributes we care about:
  gen_ai.system              openai | anthropic | aws.bedrock | ...
  gen_ai.request.model       client-requested model id
  gen_ai.response.model      server-confirmed model id (preferred)
  gen_ai.usage.input_tokens  prompt token count
  gen_ai.usage.output_tokens completion token count
  service.name               (resource attribute) caller service

Spec: https://opentelemetry.io/docs/specs/semconv/gen-ai/
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class ObservedModel:
    """Aggregate of one (system, model) pair across all GenAI spans."""

    system: str
    model: str
    invocation_count: int
    total_input_tokens: int
    total_output_tokens: int
    services: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "model": self.model,
            "invocation_count": self.invocation_count,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "services": list(self.services),
        }


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def load_otel_spans(path: Path | str) -> list[dict[str, Any]]:
    """Load an OTel-GenAI span dump from disk.

    Accepts two shapes — a bare JSON array of spans, or an object with
    a top-level "spans" / "resourceSpans" key (matches both the
    informal collector dump and the OTLP/JSON envelope).
    """
    p = Path(path)
    payload = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [s for s in payload if isinstance(s, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get("spans"), list):
            return [s for s in payload["spans"] if isinstance(s, dict)]
        if isinstance(payload.get("resourceSpans"), list):
            return list(_iter_otlp_spans(payload["resourceSpans"]))
    return []


def reconcile_runtime_with_bom(
    bom: dict[str, Any],
    spans: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Reconcile observed GenAI invocations with the static BOM.

    Returns a dict shape (see module docstring + parent agent spec):

        {
          "observed_models": [...],
          "bom_models": [...],
          "matches": [{"bom_ref": "...", "observed_model": "..."}],
          "in_runtime_not_in_bom": [...],   # shadow AI
          "in_bom_not_in_runtime": [...],   # dead inventory
          "summary": {...},
        }
    """
    observed = _aggregate_spans(spans)
    bom_components = _bom_model_components(bom)

    matches: list[dict[str, str]] = []
    matched_observed: set[tuple[str, str]] = set()
    matched_refs: set[str] = set()

    for component in bom_components:
        comp_name = (component.get("name") or "").strip()
        comp_ref = component.get("bom-ref") or component.get("bomRef") or comp_name
        if not comp_name:
            continue
        for obs in observed:
            if _model_matches(comp_name, obs.model):
                matches.append({
                    "bom_ref": str(comp_ref),
                    "observed_model": obs.model,
                    "observed_system": obs.system,
                })
                matched_observed.add((obs.system, obs.model))
                matched_refs.add(str(comp_ref))

    shadow = [
        obs.to_dict()
        for obs in observed
        if (obs.system, obs.model) not in matched_observed
    ]
    dead = [
        {
            "bom_ref": component.get("bom-ref") or component.get("bomRef") or component.get("name"),
            "name": component.get("name"),
            "type": component.get("type"),
        }
        for component in bom_components
        if (component.get("bom-ref") or component.get("bomRef") or component.get("name"))
        not in matched_refs
    ]

    total_invocations = sum(o.invocation_count for o in observed)

    return {
        "observed_models": [o.to_dict() for o in observed],
        "bom_models": [c.get("name") for c in bom_components if c.get("name")],
        "matches": matches,
        "in_runtime_not_in_bom": shadow,
        "in_bom_not_in_runtime": dead,
        "summary": {
            "total_observed_invocations": total_invocations,
            "observed_model_count": len(observed),
            "bom_model_count": len(bom_components),
            "match_count": len(matches),
            "shadow_model_count": len(shadow),
            "dead_inventory_count": len(dead),
        },
    }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_GENAI_SYSTEM_KEY = "gen_ai.system"
_GENAI_REQ_MODEL = "gen_ai.request.model"
_GENAI_RESP_MODEL = "gen_ai.response.model"
_GENAI_IN_TOKENS = "gen_ai.usage.input_tokens"
_GENAI_OUT_TOKENS = "gen_ai.usage.output_tokens"
_SERVICE_NAME = "service.name"


def _aggregate_spans(spans: Iterable[dict[str, Any]]) -> list[ObservedModel]:
    buckets: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "in": 0, "out": 0, "services": set()}
    )
    for span in spans:
        attrs = _flatten_attributes(span)
        system = _coerce_str(attrs.get(_GENAI_SYSTEM_KEY))
        # Prefer response.model — what the server actually executed.
        model = _coerce_str(attrs.get(_GENAI_RESP_MODEL)) or _coerce_str(
            attrs.get(_GENAI_REQ_MODEL)
        )
        if not system or not model:
            continue
        in_tokens = _coerce_int(attrs.get(_GENAI_IN_TOKENS))
        out_tokens = _coerce_int(attrs.get(_GENAI_OUT_TOKENS))
        service = _coerce_str(attrs.get(_SERVICE_NAME))

        bucket = buckets[(system, model)]
        bucket["count"] += 1
        bucket["in"] += in_tokens
        bucket["out"] += out_tokens
        if service:
            bucket["services"].add(service)

    out: list[ObservedModel] = []
    for (system, model), bucket in sorted(buckets.items()):
        out.append(
            ObservedModel(
                system=system,
                model=model,
                invocation_count=int(bucket["count"]),
                total_input_tokens=int(bucket["in"]),
                total_output_tokens=int(bucket["out"]),
                services=tuple(sorted(bucket["services"])),
            )
        )
    return out


def _bom_model_components(bom: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk components looking for machine-learning-model entries."""
    out: list[dict[str, Any]] = []
    components = bom.get("components") or []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        if comp.get("type") == "machine-learning-model":
            out.append(comp)
    return out


def _model_matches(bom_name: str, observed_model: str) -> bool:
    """Case-insensitive match with prefix tolerance.

    BOM may say "openai/gpt-4o" while OTel reports "gpt-4o" or
    "gpt-4o-2024-08-06". We treat any of the following as a match:

      - exact (case-insensitive)
      - one string contains the other
      - BOM name shares a leading dash-prefixed family with observed
        (gpt-4o vs gpt-4o-2024-08-06 → both start with "gpt-4o")
    """
    a = bom_name.strip().lower()
    b = observed_model.strip().lower()
    if not a or not b:
        return False
    # Strip provider prefix from BOM name ("openai/gpt-4o" -> "gpt-4o").
    if "/" in a:
        a = a.split("/", 1)[1]
    if a == b:
        return True
    if a in b or b in a:
        return True
    # Family prefix: split on '-' and require the first two segments to match.
    a_parts = a.split("-")
    b_parts = b.split("-")
    if len(a_parts) >= 2 and len(b_parts) >= 2:
        if a_parts[:2] == b_parts[:2]:
            return True
    return False


def _flatten_attributes(span: dict[str, Any]) -> dict[str, Any]:
    """Merge span attributes + resource attributes into one flat dict."""
    out: dict[str, Any] = {}
    attrs = span.get("attributes") or {}
    if isinstance(attrs, dict):
        out.update(attrs)
    resource = span.get("resource") or {}
    if isinstance(resource, dict):
        res_attrs = resource.get("attributes") or {}
        if isinstance(res_attrs, dict):
            for k, v in res_attrs.items():
                # Don't let a resource attr stomp a span-level one.
                out.setdefault(k, v)
    # Service name can also appear at the top level of normalised dumps.
    if _SERVICE_NAME not in out and isinstance(span.get("service_name"), str):
        out[_SERVICE_NAME] = span["service_name"]
    return out


def _iter_otlp_spans(resource_spans: list[Any]) -> Iterable[dict[str, Any]]:
    """Unwrap OTLP/JSON resourceSpans -> scopeSpans -> spans hierarchy."""
    for rs in resource_spans:
        if not isinstance(rs, dict):
            continue
        resource = rs.get("resource") or {}
        res_attrs = _otlp_attrs_to_dict(resource.get("attributes") or [])
        for ss in rs.get("scopeSpans") or []:
            if not isinstance(ss, dict):
                continue
            for span in ss.get("spans") or []:
                if not isinstance(span, dict):
                    continue
                yield {
                    "attributes": _otlp_attrs_to_dict(span.get("attributes") or []),
                    "resource": {"attributes": res_attrs},
                }


def _otlp_attrs_to_dict(attrs: list[Any]) -> dict[str, Any]:
    """OTLP/JSON encodes attributes as [{key, value: {...typedValue...}}]."""
    out: dict[str, Any] = {}
    for a in attrs:
        if not isinstance(a, dict):
            continue
        key = a.get("key")
        value = a.get("value") or {}
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        for type_key in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if type_key in value:
                out[key] = value[type_key]
                break
    return out


def _coerce_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _coerce_int(v: Any) -> int:
    if v is None:
        return 0
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return 0
