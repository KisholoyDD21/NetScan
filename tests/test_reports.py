"""Report renderer smoke tests."""

import csv
import json

from netscan.reports.csv_report import write_csv
from netscan.reports.html import write_html
from netscan.reports.json_report import write_json
from netscan.reports.markdown import write_markdown


def test_json_report(sample_result, tmp_path) -> None:
    path = write_json(sample_result, tmp_path / "scan.json")
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == "1.0"


def test_csv_report_has_rows(sample_result, tmp_path) -> None:
    path = write_csv(sample_result, tmp_path / "scan.csv")
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["port"] == "22"


def test_markdown_report(sample_result, tmp_path) -> None:
    path = write_markdown(sample_result, tmp_path / "scan.md")
    assert "Open ports" in path.read_text(encoding="utf-8")


def test_html_report_escapes_hostname(sample_result, tmp_path) -> None:
    sample_result.hosts[0].hostname = "<script>alert(1)</script>"
    path = write_html(sample_result, tmp_path / "scan.html")
    text = path.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in text
    assert "Changes since last scan" not in text



def test_html_renders_empty_result(sample_result, tmp_path) -> None:
    sample_result.hosts = []
    path = write_html(sample_result, tmp_path / "empty.html")
    assert "No open ports were reported" in path.read_text(encoding="utf-8")



def test_csv_escapes_formula_leading_banner(sample_result, tmp_path) -> None:
    sample_result.hosts[0].ports[0].service.product = "=HYPERLINK(\"https://bad.example\")"
    path = write_csv(sample_result, tmp_path / "safe.csv")
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["product"].startswith("'=")



def test_markdown_includes_cve_and_diff_sections(sample_result, tmp_path) -> None:
    from netscan.models import CveCandidate

    sample_result.hosts[0].cve_candidates.append(
        CveCandidate("CVE-2025-1234", "https://nvd.nist.gov/vuln/detail/CVE-2025-1234", "Demo issue", "7.5")
    )
    sample_result.changes_since_previous = {"new_hosts": ["192.0.2.1"]}
    path = write_markdown(sample_result, tmp_path / "changes.md")
    content = path.read_text(encoding="utf-8")
    assert "Potential CVE leads" in content
    assert "Changes since last scan" in content
