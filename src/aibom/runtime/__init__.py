"""Runtime telemetry reconciliation — bridge between live OTel-GenAI
traces and the static AiBOM.

The static scanner sees what the source code *declares* about model
usage; OpenTelemetry GenAI semantic-conventions traces see what the
running service actually *invokes*. Reconciling the two surfaces two
high-value gaps every AIBOM competitor charges for:

  - shadow AI            — models observed in runtime that the BOM
                            doesn't know about (engineers calling
                            unauthorised providers from notebooks,
                            dynamic prompts, etc.)
  - dead inventory       — models the BOM declares but nobody is
                            actually invoking (decom candidates,
                            policy hangovers)

We intentionally do NOT take a hard dependency on the
`opentelemetry-api` package — the OTel ecosystem is heavyweight, and
operators typically have a collector already exporting JSONL/JSON
spans. The reconciler consumes plain dicts so any source (OTLP-JSON
file, Jaeger query, Tempo HTTP API, etc.) can feed it.

Public surface:
  - reconcile_runtime_with_bom(bom, spans) -> dict
  - load_otel_spans(path) -> list[dict]
"""

from aibom.runtime.otel_genai import (
    ObservedModel,
    load_otel_spans,
    reconcile_runtime_with_bom,
)

__all__ = [
    "ObservedModel",
    "load_otel_spans",
    "reconcile_runtime_with_bom",
]
