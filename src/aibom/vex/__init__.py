"""VEX / VDR — known-bad component cross-reference + CycloneDX VEX emission.

  feed.py     curated registry + cross-reference (HF malicious models,
              typosquatted PyPI/npm AI packages, withdrawn provider keys)
  cdx_vex.py  emit a CycloneDX 1.6 'vulnerabilities' array suitable for
              ingestion by Dependency-Track / Snyk / any CDX-aware tool
"""

from aibom.vex.cdx_vex import emit_vex_for_bom, merge_vex_into_bom
from aibom.vex.feed import (
    DEFAULT_VEX_FEED,
    VexEntry,
    cross_reference,
    load_feed,
)
from aibom.vex.kev import (
    KevEntry,
    cross_reference_kev,
    load_kev_feed,
)

__all__ = [
    "DEFAULT_VEX_FEED",
    "KevEntry",
    "VexEntry",
    "cross_reference",
    "cross_reference_kev",
    "emit_vex_for_bom",
    "load_feed",
    "load_kev_feed",
    "merge_vex_into_bom",
]
