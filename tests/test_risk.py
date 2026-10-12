"""Tests for heuristic risk scoring."""

from netscan.models import Host, Port, ScriptOutput, Service
from netscan.risk import score_host, score_hosts


def test_risky_ports_increase_score() -> None:
    host = Host(address="192.0.2.1", ports=[Port(23, "tcp", "open", service=Service(name="telnet"))])
    score, level = score_host(host)
    assert score >= 20
    assert level in {"Medium", "High", "Critical"}


def test_score_is_capped() -> None:
    host = Host(address="192.0.2.2", ports=[Port(port, "tcp", "open") for port in [21, 23, 445, 1433, 3306, 3389, 6379, 9200, 27017]])
    score, level = score_host(host)
    assert score == 100
    assert level == "Critical"


def test_service_banners_and_scripts_add_risk() -> None:
    plain = Host(address="192.0.2.3", ports=[Port(8080, "tcp", "open")])
    banner = Host(address="192.0.2.4", ports=[Port(8080, "tcp", "open", service=Service(name="http", product="Demo", version="1.2"), scripts=[ScriptOutput("http-title", "admin")])])
    assert score_host(banner)[0] > score_host(plain)[0]
    score_hosts([plain, banner])
    assert banner.risk_score > plain.risk_score
