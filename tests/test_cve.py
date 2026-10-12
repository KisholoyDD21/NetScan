"""Optional CVE enrichment tests use mocked offline lookup responses."""

import json

from netscan.cve import _cvss_score, _lookup, enrich_cve_candidates
from netscan.models import CveCandidate, Host, Port, ScanMetadata, ScanResult, Service


def test_cve_enrichment_is_opt_in_and_attaches_candidates(monkeypatch) -> None:
    result = ScanResult(metadata=ScanMetadata(profile="service"), hosts=[Host(address="127.0.0.1", ports=[
        Port(80, "tcp", "open", service=Service(name="http", product="Example", version="1.2"))])])
    monkeypatch.setattr("netscan.cve._lookup", lambda keyword, timeout: [CveCandidate("CVE-2025-1234", "https://nvd.nist.gov/vuln/detail/CVE-2025-1234", "Example issue", "7.5")])
    warnings = enrich_cve_candidates(result)
    assert warnings == []
    assert result.hosts[0].cve_candidates[0].cve_id == "CVE-2025-1234"


def test_cve_enrichment_warns_nonfatally(monkeypatch) -> None:
    result = ScanResult(metadata=ScanMetadata(profile="service"), hosts=[Host(address="127.0.0.1", ports=[
        Port(80, "tcp", "open", service=Service(name="http", product="Example", version="1.2"))])])
    def fail(keyword, timeout):
        raise TimeoutError("simulated timeout")
    monkeypatch.setattr("netscan.cve._lookup", fail)
    warnings = enrich_cve_candidates(result)
    assert "NVD lookup failed" in warnings[0]


def test_cvss_score_selects_first_supported_metric() -> None:
    assert _cvss_score({"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]}) == "8.1"
    assert _cvss_score({}) == ""



def test_lookup_parses_nvd_response(monkeypatch) -> None:
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-2025-9999", "descriptions": [
        {"lang": "en", "value": "Test description"}], "metrics": {"cvssMetricV31": [
        {"cvssData": {"baseScore": 6.5}}]}}}, {"cve": {"id": "bad-id"}}]}
    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read(self):
            return json.dumps(payload).encode("utf-8")
    def fake_urlopen(request, timeout):
        assert "keywordSearch=Example" in request.full_url
        assert timeout == 3
        return FakeResponse()
    monkeypatch.setattr("netscan.cve.urlopen", fake_urlopen)
    candidates = _lookup("Example 1.2", timeout_seconds=3)
    assert len(candidates) == 1
    assert candidates[0].cvss_score == "6.5"
