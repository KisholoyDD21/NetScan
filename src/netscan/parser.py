"""Parse Nmap XML output into typed NetScan models."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from netscan.models import Host, Port, ScanMetadata, ScanResult, ScriptOutput, Service


def parse_nmap_xml(xml_data: str, metadata: ScanMetadata) -> ScanResult:
    """Parse Nmap XML safely; malformed XML raises a descriptive ValueError."""
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        raise ValueError(f"Nmap returned invalid XML: {exc}") from exc
    hosts: list[Host] = []
    for node in root.findall("host"):
        host = _parse_host(node)
        hosts.append(host)
    version = root.get("version")
    if version:
        metadata.nmap_version = version
    return ScanResult(metadata=metadata, hosts=hosts)


def _parse_host(node: ET.Element) -> Host:
    """Parse one XML host node."""
    status_node = node.find("status")
    status = status_node.get("state", "unknown") if status_node is not None else "unknown"
    reason = status_node.get("reason", "") if status_node is not None else ""
    address_node = next((n for n in node.findall("address") if n.get("addrtype") in {"ipv4", "ipv6"}), None)
    address = address_node.get("addr", "unknown") if address_node is not None else "unknown"
    hostname_node = node.find("./hostnames/hostname")
    hostname = hostname_node.get("name", "") if hostname_node is not None else ""
    ports = [_parse_port(p) for p in node.findall("./ports/port")]
    os_matches = [m.get("name", "") for m in node.findall("./os/osmatch") if m.get("name")]
    return Host(address=address, hostname=hostname, status=status, reason=reason, ports=ports, os_matches=os_matches)


def _parse_port(node: ET.Element) -> Port:
    """Parse one port node and all associated service/script records."""
    state_node = node.find("state")
    service_node = node.find("service")
    state = state_node.get("state", "unknown") if state_node is not None else "unknown"
    reason = state_node.get("reason", "") if state_node is not None else ""
    service: Service = Service()
    if service_node is not None:
        confidence = service_node.get("conf")
        service = Service(
            name=service_node.get("name", "unknown"), product=service_node.get("product", ""),
            version=service_node.get("version", ""), extra_info=service_node.get("extrainfo", ""),
            tunnel=service_node.get("tunnel", ""), method=service_node.get("method", ""),
            confidence=int(confidence) if confidence and confidence.isdigit() else None,
        )
    scripts = [ScriptOutput(s.get("id", "unknown"), s.get("output", "")) for s in node.findall("script")]
    return Port(number=int(node.get("portid", "0")), protocol=node.get("protocol", "tcp"),
                state=state, reason=reason, service=service, scripts=scripts)
