"""Shared test fixtures; tests do not require an installed Nmap binary."""

from pathlib import Path

import pytest

from netscan.models import Host, Port, ScanMetadata, ScanResult, Service

ROOT = Path(__file__).parent


@pytest.fixture
def sample_xml() -> str:
    """Return a known-good Nmap XML fixture."""
    return (ROOT / "fixtures" / "sample.xml").read_text(encoding="utf-8")


@pytest.fixture
def sample_result() -> ScanResult:
    """Return a representative scan result for report and diff tests."""
    host = Host(address="127.0.0.1", hostname="localhost", status="up", ports=[
        Port(number=22, protocol="tcp", state="open", service=Service(name="ssh", product="OpenSSH", version="9.6")),
        Port(number=443, protocol="tcp", state="open", service=Service(name="https")),
    ])
    return ScanResult(metadata=ScanMetadata(profile="quick", nmap_version="7.94", started_at="2026-01-01T00:00:00Z"), hosts=[host])
