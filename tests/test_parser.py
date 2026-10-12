"""Tests for XML parsing and model serialization."""

import pytest

from netscan.models import ScanMetadata, ScanResult
from netscan.parser import parse_nmap_xml


def test_parse_ports_and_host(sample_xml: str) -> None:
    result = parse_nmap_xml(sample_xml, ScanMetadata(profile="quick"))
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.address == "127.0.0.1"
    assert host.hostname == "localhost"
    assert host.ports[0].service.banner == "OpenSSH 9.6"
    assert host.ports[1].state == "closed"
    assert host.os_matches == ["Linux 5.x"]


def test_empty_xml_valid() -> None:
    result = parse_nmap_xml('<nmaprun version="7.94"/>', ScanMetadata(profile="discovery"))
    assert result.hosts == []
    assert result.metadata.nmap_version == "7.94"


def test_invalid_xml_raises() -> None:
    with pytest.raises(ValueError, match="invalid XML"):
        parse_nmap_xml("<nmaprun>", ScanMetadata(profile="quick"))


def test_json_round_trip(sample_result) -> None:
    loaded = ScanResult.from_dict(sample_result.to_dict())
    assert loaded.hosts[0].ports[0].service.version == "9.6"
