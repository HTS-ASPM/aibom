"""Compliance pack — auditor-friendly reports built from a ScanResult.

  annex_iv      EU AI Act Annex IV technical-file report (HTML)
  nist_rmf      NIST AI RMF GAI profile crosswalk (HTML)

These are read-only consumers of the existing AiBOM pipeline — they
re-shape findings, never alter them.
"""

from aibom.compliance.annex_iv import generate_annex_iv_html
from aibom.compliance.iso_42001 import generate_iso_42001_html
from aibom.compliance.nist_rmf import generate_nist_rmf_html

__all__ = ["generate_annex_iv_html", "generate_iso_42001_html", "generate_nist_rmf_html"]
