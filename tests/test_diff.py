"""Tests for scan-to-scan comparison."""

from copy import deepcopy

from netscan.diff import compare_scans
from netscan.models import Host, Port, ScanMetadata, ScanResult, Service


def test_detects_new_hosts_and_ports(sample_result) -> None:
    new = ScanResult(metadata=ScanMetadata(profile="quick"), hosts=[
        deepcopy(sample_result.hosts[0]), Host(address="192.0.2.1", status="up", ports=[Port(8080, "tcp", "open")])])
    new.hosts[0].ports.append(Port(8443, "tcp", "open", service=Service(name="https")))
    changes = compare_scans(sample_result, new)
    assert "192.0.2.1" in changes["new_hosts"]
    assert any(item["port"] == 8443 for item in changes["new_ports"])


def test_detects_closed_port_and_service_change(sample_result) -> None:
    new_host = Host(address="127.0.0.1", status="up", ports=[Port(22, "tcp", "open", service=Service(name="ssh", product="OpenSSH", version="10.0"))])
    new = ScanResult(metadata=ScanMetadata(profile="quick"), hosts=[new_host])
    changes = compare_scans(sample_result, new)
    assert any(item["port"] == 443 for item in changes["closed_ports"])
    assert len(changes["changed_services"]) == 1
