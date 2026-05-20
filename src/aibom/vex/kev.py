"""CISA KEV (Known Exploited Vulnerabilities) cross-reference.

We deliberately do NOT fetch the KEV catalog at scanner runtime —
fleet machines should not phone home to cisa.gov. Instead the deployer
caches the KEV JSON to disk and points the scanner at it via either:

    AIBOM_KEV_FEED=/var/lib/aibom/kev.json   (env var)
    aibom kev <bom> --kev-feed /path/kev.json   (CLI)

KEV JSON layout (from
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json):

  {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "...",
    "dateReleased": "...",
    "vulnerabilities": [
      {
        "cveID": "CVE-2024-XXXXX",
        "vendorProject": "...",
        "product": "...",
        "vulnerabilityName": "...",
        "dateAdded": "YYYY-MM-DD",
        "shortDescription": "...",
        "requiredAction": "...",
        "knownRansomwareCampaignUse": "Known" | "Unknown",
        "notes": "..."
      }
    ]
  }

We walk the BOM's `vulnerabilities[]` array (populated by P7's VEX
merge or by the SBOM half of the unified BOM) and emit one finding per
KEV match. The matched BOM vulnerability entry is also annotated in
place so downstream consumers see KEV provenance directly on the
vulnerability record, not as a parallel structure.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from aibom.models import Finding, MatchEvidence


# Official CISA KEV catalog feed.
CISA_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# Default on-disk cache for the KEV catalog when no explicit path is given.
DEFAULT_KEV_CACHE_PATH = Path.home() / ".aibom" / "kev.json"


@dataclass(frozen=True, slots=True)
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    short_description: str
    known_ransomware: bool


def load_kev_feed(path: Path | None = None) -> dict[str, KevEntry]:
    """Load + index the KEV catalog by upper-cased CVE id. Returns {} when no file is available.

    Resolution order:
      1. explicit `path` argument
      2. AIBOM_KEV_FEED env var
      3. ``~/.aibom/kev.json`` if it exists (populated by `aibom kev-refresh`)
    """
    candidate = path or _env_feed_path() or _default_cache_if_exists()
    if candidate is None or not candidate.exists():
        return {}
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, KevEntry] = {}
    for entry in payload.get("vulnerabilities") or []:
        cve = str(entry.get("cveID") or "").upper().strip()
        if not cve:
            continue
        out[cve] = KevEntry(
            cve_id=cve,
            vendor=str(entry.get("vendorProject") or ""),
            product=str(entry.get("product") or ""),
            name=str(entry.get("vulnerabilityName") or ""),
            date_added=str(entry.get("dateAdded") or ""),
            short_description=str(entry.get("shortDescription") or ""),
            known_ransomware=str(entry.get("knownRansomwareCampaignUse") or "").lower() == "known",
        )
    return out


def cross_reference_kev(
    bom: dict[str, Any],
    kev_index: dict[str, KevEntry] | None = None,
    *,
    annotate_in_place: bool = True,
) -> list[Finding]:
    """Emit one Finding per KEV match against BOM `vulnerabilities[]`.

    When `annotate_in_place` is True (default) the matched BOM
    vulnerability gets a `analysis.kev` block and an updated
    `analysis.detail` so the augmented BOM is self-describing.
    """
    index = kev_index if kev_index is not None else load_kev_feed()
    if not index:
        return []
    findings: list[Finding] = []
    for vuln in bom.get("vulnerabilities") or []:
        cve = str(vuln.get("id") or "").upper().strip()
        if not cve.startswith("CVE-"):
            continue
        kev = index.get(cve)
        if kev is None:
            continue
        affects_ref = ""
        affects_list = vuln.get("affects") or []
        if affects_list and isinstance(affects_list, list):
            first = affects_list[0]
            if isinstance(first, dict):
                affects_ref = str(first.get("ref", ""))
        severity = "critical" if kev.known_ransomware else "high"
        findings.append(
            Finding(
                finding_id=f"kev:{kev.cve_id}:{affects_ref or 'unknown'}",
                rule_id=f"kev.{kev.cve_id}",
                category="kev",
                name=f"CISA KEV: {kev.cve_id}",
                severity=severity,
                confidence="high",
                path=affects_ref or kev.product or kev.vendor,
                detector="cisa-kev",
                entity_type="component",
                source_kind="bom",
                summary=(
                    f"{kev.cve_id} is on the CISA KEV catalog "
                    f"({kev.vendor} {kev.product}; added {kev.date_added}). "
                    + ("Known ransomware campaign use." if kev.known_ransomware else "Active exploitation observed.")
                ),
                evidence=[
                    MatchEvidence(line=0, snippet=kev.short_description[:220], match=kev.cve_id),
                ],
                metadata={
                    "cve_id": kev.cve_id,
                    "kev_vendor": kev.vendor,
                    "kev_product": kev.product,
                    "kev_date_added": kev.date_added,
                    "known_ransomware": kev.known_ransomware,
                    "bom_ref": affects_ref,
                },
            )
        )
        if annotate_in_place:
            analysis = vuln.setdefault("analysis", {})
            analysis["kev"] = {
                "cve_id": kev.cve_id,
                "vendor": kev.vendor,
                "product": kev.product,
                "date_added": kev.date_added,
                "known_ransomware_campaign_use": kev.known_ransomware,
            }
            existing_detail = str(analysis.get("detail") or "")
            kev_note = f"CISA KEV — {kev.cve_id}; ransomware: {'Known' if kev.known_ransomware else 'Unknown'}"
            analysis["detail"] = (existing_detail + " | " + kev_note).strip(" |") if existing_detail else kev_note
            # Promote exploitable state when KEV present.
            analysis["state"] = "exploitable"
    return findings


def _env_feed_path() -> Path | None:
    val = os.environ.get("AIBOM_KEV_FEED")
    return Path(val) if val else None


def _default_cache_if_exists() -> Path | None:
    return DEFAULT_KEV_CACHE_PATH if DEFAULT_KEV_CACHE_PATH.exists() else None


# --------------------------------------------------------------------------- #
# Catalog auto-refresh (P16)
# --------------------------------------------------------------------------- #

class KevRefreshError(RuntimeError):
    """Raised when the KEV catalog cannot be fetched or written."""


def _default_fetcher(url: str) -> bytes:
    """Minimal urllib-backed HTTPS GET. Pulled out so tests can inject."""
    request = urllib.request.Request(url, headers={"User-Agent": "aibom-kev-refresh/1"})
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:  # noqa: S310
            return resp.read()
    except urllib.error.URLError as exc:  # pragma: no cover — network path
        raise KevRefreshError(f"failed to fetch KEV feed: {exc}") from exc


def refresh_kev_feed(
    destination: Path | str | None = None,
    *,
    source_url: str | None = None,
    fetcher: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Fetch the CISA KEV catalog and write it atomically to ``destination``.

    Returns a small summary dict::

        {"vulnerabilities": N, "catalog_version": "...", "destination": "/path"}

    The write is atomic — a tmp file is written + renamed; if the
    fetcher raises, no destination file is touched.
    """
    dest = Path(destination) if destination is not None else DEFAULT_KEV_CACHE_PATH
    url = source_url or CISA_KEV_FEED_URL
    fetch = fetcher or _default_fetcher

    raw = fetch(url)
    if not isinstance(raw, (bytes, bytearray)):
        raise KevRefreshError("fetcher must return bytes")
    try:
        decoded = raw.decode("utf-8")
        payload = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KevRefreshError(f"KEV feed is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or "vulnerabilities" not in payload:
        raise KevRefreshError("KEV feed is missing the 'vulnerabilities' array")

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(raw)
    tmp.replace(dest)

    vulns = payload.get("vulnerabilities") or []
    return {
        "vulnerabilities": len(vulns),
        "catalog_version": payload.get("catalogVersion") or payload.get("catalog_version"),
        "date_released": payload.get("dateReleased") or payload.get("date_released"),
        "destination": str(dest),
        "source_url": url,
    }
