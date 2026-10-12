"""Typed data models used by scanning, analysis, and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ScriptOutput:
    """Output from one Nmap script."""

    script_id: str
    output: str


@dataclass(slots=True)
class Service:
    """Service identification returned by Nmap."""

    name: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""
    method: str = ""
    confidence: int | None = None

    @property
    def banner(self) -> str:
        """Return a compact service banner."""
        parts = [self.product, self.version, self.extra_info]
        return " ".join(part for part in parts if part).strip()


@dataclass(slots=True)
class Port:
    """A TCP or UDP port and its observed state."""

    number: int
    protocol: str
    state: str
    reason: str = ""
    service: Service = field(default_factory=Service)
    scripts: list[ScriptOutput] = field(default_factory=list)


@dataclass(slots=True)
class CveCandidate:
    """Potential CVE lead from optional enrichment; not confirmation of exposure."""

    cve_id: str
    url: str
    description: str = ""
    cvss_score: str = ""


@dataclass(slots=True)
class Host:
    """One scanned host and its discovered ports."""

    address: str
    hostname: str = ""
    status: str = "unknown"
    reason: str = ""
    ports: list[Port] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Low"
    cve_candidates: list[CveCandidate] = field(default_factory=list)


@dataclass(slots=True)
class ScanMetadata:
    """Execution metadata for a scan run."""

    profile: str
    nmap_version: str = "unknown"
    command: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    scanner_version: str = "0.1.0"
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    """Versioned, serializable result of a scan session."""

    metadata: ScanMetadata
    hosts: list[Host] = field(default_factory=list)
    schema_version: str = "1.0"
    changes_since_previous: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result to plain JSON-compatible values."""
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ScanResult":
        """Build a result from decoded JSON while tolerating missing optional fields."""
        metadata = ScanMetadata(**raw.get("metadata", {}))
        hosts: list[Host] = []
        for host_raw in raw.get("hosts", []):
            ports: list[Port] = []
            for port_raw in host_raw.get("ports", []):
                service = Service(**port_raw.get("service", {}))
                scripts = [ScriptOutput(**item) for item in port_raw.get("scripts", [])]
                ports.append(Port(**{**port_raw, "service": service, "scripts": scripts}))
            candidates = [CveCandidate(**item) for item in host_raw.get("cve_candidates", [])]
            hosts.append(Host(**{**host_raw, "ports": ports, "cve_candidates": candidates}))
        return cls(metadata=metadata, hosts=hosts, schema_version=raw.get("schema_version", "1.0"),
                   changes_since_previous=raw.get("changes_since_previous"))
