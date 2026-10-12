"""PDF writer tests mock WeasyPrint so they do not require native dependencies."""

import sys
from types import SimpleNamespace

import pytest

from netscan.exceptions import ReportError
from netscan.reports.pdf import write_pdf


def test_pdf_optional_dependency_missing(monkeypatch, sample_result, tmp_path) -> None:
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    with pytest.raises(ReportError, match="optional 'pdf' extra"):
        write_pdf(sample_result, tmp_path / "report.pdf")


def test_pdf_writer_uses_html_source(monkeypatch, sample_result, tmp_path) -> None:
    class FakeHTML:
        def __init__(self, filename):
            self.filename = filename
        def write_pdf(self, filename):
            from pathlib import Path
            Path(filename).write_bytes(b"%PDF-fake")
    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=FakeHTML))
    destination = write_pdf(sample_result, tmp_path / "report.pdf")
    assert destination.read_bytes() == b"%PDF-fake"
    assert not (tmp_path / "report.source.html").exists()


def test_pdf_writer_reports_rendering_failure(monkeypatch, sample_result, tmp_path) -> None:
    class BrokenHTML:
        def __init__(self, filename):
            self.filename = filename
        def write_pdf(self, filename):
            raise RuntimeError("render broke")
    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=BrokenHTML))
    with pytest.raises(ReportError, match="rendering failed"):
        write_pdf(sample_result, tmp_path / "bad.pdf")
    assert not (tmp_path / "bad.source.html").exists()
