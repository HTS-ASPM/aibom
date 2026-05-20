"""HTS-ASPM integration glue.

This package builds the ASPM ingest envelope (a richer payload than the
raw CycloneDX BOM) and provides a thin push wrapper on top of
``aibom.aspm_push``.

The protocol contract is documented in :mod:`aibom.hts_aspm.payload` and
in ``docs/hts_aspm_protocol.md``.
"""

from __future__ import annotations

from aibom.hts_aspm.payload import (
    ASPM_CONTENT_TYPE,
    SCHEMA_VERSION,
    build_aspm_payload,
    canonical_json_bytes,
)
from aibom.hts_aspm.push import push_aspm_payload

__all__ = [
    "ASPM_CONTENT_TYPE",
    "SCHEMA_VERSION",
    "build_aspm_payload",
    "canonical_json_bytes",
    "push_aspm_payload",
]
