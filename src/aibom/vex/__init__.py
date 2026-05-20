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
    CISA_KEV_FEED_URL,
    DEFAULT_KEV_CACHE_PATH,
    KevEntry,
    KevRefreshError,
    cross_reference_kev,
    load_kev_feed,
    refresh_kev_feed,
)

__all__ = [
    "CISA_KEV_FEED_URL",
    "DEFAULT_KEV_CACHE_PATH",
    "DEFAULT_VEX_FEED",
    "KevEntry",
    "KevRefreshError",
    "VexEntry",
    "cross_reference",
    "cross_reference_kev",
    "emit_vex_for_bom",
    "load_feed",
    "load_kev_feed",
    "merge_vex_into_bom",
    "refresh_kev_feed",
]
