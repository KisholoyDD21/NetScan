"""Compare two stored scan results without performing network activity."""

from __future__ import annotations

from typing import Any

from netscan.models import Host, ScanResult


def compare_scans(old: ScanResult, new: ScanResult) -> dict[str, Any]:
    """Describe new hosts, added/closed ports, and service changes."""
    old_hosts = {host.address: host for host in old.hosts}
    new_hosts = {host.address: host for host in new.hosts}
    changes: dict[str, Any] = {"new_hosts": [], "removed_hosts": [], "new_ports": [],
                               "closed_ports": [], "changed_services": []}
    changes["new_hosts"] = sorted(set(new_hosts) - set(old_hosts))
    changes["removed_hosts"] = sorted(set(old_hosts) - set(new_hosts))
    for address in sorted(set(old_hosts) & set(new_hosts)):
        _compare_host(address, old_hosts[address], new_hosts[address], changes)
    return changes


def _compare_host(address: str, old: Host, new: Host, changes: dict[str, Any]) -> None:
    """Compare port and service fingerprints for one shared host."""
    old_ports = {(p.protocol, p.number): p for p in old.ports if p.state == "open"}
    new_ports = {(p.protocol, p.number): p for p in new.ports if p.state == "open"}
    for key in sorted(set(new_ports) - set(old_ports)):
        changes["new_ports"].append({"host": address, "protocol": key[0], "port": key[1]})
    for key in sorted(set(old_ports) - set(new_ports)):
        changes["closed_ports"].append({"host": address, "protocol": key[0], "port": key[1]})
    for key in sorted(set(old_ports) & set(new_ports)):
        before, after = old_ports[key].service, new_ports[key].service
        old_fingerprint = (before.name, before.product, before.version)
        new_fingerprint = (after.name, after.product, after.version)
        if old_fingerprint != new_fingerprint:
            changes["changed_services"].append({"host": address, "protocol": key[0], "port": key[1],
                "old": " ".join(x for x in old_fingerprint if x),
                "new": " ".join(x for x in new_fingerprint if x)})
