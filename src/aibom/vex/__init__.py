"""VEX / VDR — known-bad component cross-reference + CycloneDX VEX emission.

  feed.py     curated registry + cross-reference (HF malicious models,
              typosquatted PyPI/npm AI packages, withdrawn provider keys)
  cdx_vex.py  emit a CycloneDX 1.6 'vulnerabilities' array suitable for
              ingestion by Dependency-Track / Snyk / any CDX-aware tool
"""

from aibom.vex.cdx_vex import emit_vex_for_bom
from aibom.vex.feed import (
    DEFAULT_VEX_FEED,
    VexEntry,
    cross_reference,
    load_feed,
)

__all__ = [
    "DEFAULT_VEX_FEED",
    "VexEntry",
    "cross_reference",
    "emit_vex_for_bom",
    "load_feed",
]
