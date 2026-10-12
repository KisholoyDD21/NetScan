"""Optional NVD keyword lookup for review leads; disabled unless explicitly requested."""

from __future__ import annotations

import json
import logging
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from netscan.models import CveCandidate, ScanResult

LOGGER = logging.getLogger(__name__)
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def enrich_cve_candidates(result: ScanResult, timeout_seconds: int = 8, max_queries: int = 5) -> list[str]:
    """Attach a small set of NVD keyword-search leads and return non-fatal warnings.

    Banners can be incomplete or spoofed; results are review candidates, not findings.
    Network calls occur only when this function is explicitly invoked by the CLI flag.
    """
    warnings: list[str] = []
    queries: dict[str, set[str]] = {}
    for host in result.hosts:
        for port in host.ports:
            product = port.service.product.strip()
            version = port.service.version.strip()
            if not product or not version:
                continue
            keyword = f"{product} {version}".strip()
            queries.setdefault(keyword, set()).add(host.address)
    for keyword, host_addresses in list(queries.items())[:max_queries]:
        try:
            candidates = _lookup(keyword, timeout_seconds)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError) as exc:
            warnings.append(f"NVD lookup failed for {keyword!r}: {exc}")
            LOGGER.warning("Optional NVD enrichment failed for %s: %s", keyword, exc)
            continue
        for host in result.hosts:
            if host.address in host_addresses:
                known = {item.cve_id for item in host.cve_candidates}
                host.cve_candidates.extend(item for item in candidates if item.cve_id not in known)
    if len(queries) > max_queries:
        warnings.append(f"NVD query limit reached ({max_queries}); {len(queries) - max_queries} service/version queries skipped.")
    return warnings


def _lookup(keyword: str, timeout_seconds: int) -> list[CveCandidate]:
    """Query NVD keyword search and reduce results to a compact model."""
    url = f"{NVD_ENDPOINT}?{urlencode({'keywordSearch': keyword, 'resultsPerPage': '5'})}"
    request = Request(url, headers={"User-Agent": "NetScan/0.1.0 optional-cve-enrichment"})
    with urlopen(request, timeout=timeout_seconds) as response:
        data = json.loads(response.read().decode("utf-8"))
    candidates: list[CveCandidate] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = str(cve.get("id", "")).strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            continue
        descriptions = cve.get("descriptions", [])
        description = next((str(entry.get("value", "")) for entry in descriptions if entry.get("lang") == "en"), "")
        score = _cvss_score(cve.get("metrics", {}))
        candidates.append(CveCandidate(cve_id=cve_id, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                       description=description[:600], cvss_score=score))
    return candidates


def _cvss_score(metrics: dict[str, object]) -> str:
    """Return the first available CVSS base score without implying applicability."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if isinstance(values, list) and values:
            metric = values[0]
            if isinstance(metric, dict):
                cvss_data = metric.get("cvssData", {})
                if isinstance(cvss_data, dict) and cvss_data.get("baseScore") is not None:
                    return str(cvss_data["baseScore"])
    return ""
