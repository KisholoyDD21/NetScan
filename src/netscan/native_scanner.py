"""Pure Python network scanner using standard library sockets and asyncio.

Provides fast, standalone TCP port scanning and basic host discovery
without requiring external binaries or drivers (e.g. Nmap or Npcap).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from datetime import UTC, datetime

from netscan.exceptions import ScanExecutionError
from netscan.models import Host, Port, ScanMetadata, ScanResult, Service
from netscan.risk import score_hosts

LOGGER = logging.getLogger(__name__)

# Standard top 100 TCP ports (matching Nmap's top TCP ports)
NATIVE_TOP_100_PORTS: list[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

COMMON_PORT_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


def resolve_service_name(port: int, proto: str = "tcp") -> str:
    """Return common service name for a port, falling back to socket.getservbyport."""
    if port in COMMON_PORT_NAMES:
        return COMMON_PORT_NAMES[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def resolve_hostname(ip: str) -> str:
    """Attempt reverse DNS lookup for an IP address."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except OSError:
        return ""


def _parse_custom_ports(flags: list[str]) -> list[int]:
    """Extract port numbers from custom flags if -p or --top-ports is given."""
    ports: list[int] = []
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag == "-p" and i + 1 < len(flags):
            val = flags[i + 1]
            for part in val.split(","):
                part = part.strip()
                if "-" in part:
                    start_s, end_s = part.split("-", 1)
                    if start_s.isdigit() and end_s.isdigit():
                        start, end = int(start_s), int(end_s)
                        ports.extend(range(max(1, start), min(65535, end) + 1))
                elif part.isdigit():
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.append(p)
            i += 1
        elif flag == "--top-ports" and i + 1 < len(flags):
            val = flags[i + 1]
            if val.isdigit():
                count = int(val)
                ports.extend(NATIVE_TOP_100_PORTS[:count])
            i += 1
        i += 1
    return sorted(set(ports)) if ports else NATIVE_TOP_100_PORTS


class NativeScanner:
    """Pure Python network scanner without external Nmap dependency."""

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds
        self.nmap_version = "native-python"

    def scan(
        self,
        target: str,
        profile: str,
        custom_flags: list[str] | None = None,
        allow_vuln: bool = False,
        engine: str = "native",
    ) -> ScanResult:
        """Scan one in-scope target using native Python sockets."""
        warnings: list[str] = []
        if profile == "vuln" and not allow_vuln:
            raise ScanExecutionError("The vuln profile requires explicit --allow-vuln-scripts acknowledgment.")
        if profile == "vuln":
            warnings.append("NSE scripts require Nmap; native engine performed port and banner discovery only.")
        if profile == "stealth":
            warnings.append("SYN stealth scanning requires raw sockets; downgraded to TCP connect scan.")
        if profile == "os-detect":
            warnings.append("OS detection in native engine is heuristic based on discovered ports.")
        if profile == "udp-top":
            warnings.append("UDP port scanning in native engine is limited; TCP connect used for reachability.")

        started = datetime.now(UTC)
        begin = time.monotonic()
        LOGGER.info("Starting native scan profile=%s target=%s", profile, target)

        ports_to_scan: list[int]
        grab_banners = profile in {"service", "vuln", "custom"}
        if profile == "discovery":
            ports_to_scan = [80, 443, 22, 135, 445, 8080, 53, 3389]
        elif profile == "full-tcp":
            ports_to_scan = list(range(1, 65536))
        elif profile == "custom":
            ports_to_scan = _parse_custom_ports(custom_flags or [])
        else:
            ports_to_scan = NATIVE_TOP_100_PORTS

        open_ports = asyncio.run(
            self._scan_ports_async(target, ports_to_scan, grab_banners=grab_banners)
        )

        elapsed = time.monotonic() - begin
        is_up = bool(open_ports) or target in {"127.0.0.1", "localhost", "::1"}
        status = "up" if is_up else "down"
        reason = "syn-ack" if open_ports else ("localhost-response" if is_up else "no-response")

        os_matches: list[str] = []
        if profile == "os-detect" or profile == "service":
            open_port_numbers = {p.number for p in open_ports}
            if 135 in open_port_numbers or 445 in open_port_numbers:
                os_matches.append("Microsoft Windows")
            elif 22 in open_port_numbers:
                os_matches.append("Linux / Unix")

        hostname = resolve_hostname(target) if target not in {"127.0.0.1", "localhost"} else "localhost"

        host = Host(
            address=target,
            hostname=hostname,
            status=status,
            reason=reason,
            ports=open_ports,
            os_matches=os_matches,
        )

        hosts = [host]
        score_hosts(hosts)

        command = ["netscan-native", "--profile", profile, target]
        metadata = ScanMetadata(
            profile=profile,
            nmap_version=self.nmap_version,
            command=command,
            started_at=started.isoformat(),
            finished_at=datetime.now(UTC).isoformat(),
            duration_seconds=round(elapsed, 3),
            scanner_version="0.1.0",
            warnings=warnings,
        )

        LOGGER.info("Completed native scan target=%s open_ports=%d duration=%.2fs", target, len(open_ports), elapsed)
        return ScanResult(metadata=metadata, hosts=hosts)

    async def _scan_ports_async(
        self,
        host: str,
        ports: list[int],
        grab_banners: bool = False,
    ) -> list[Port]:
        """Scan TCP ports concurrently using asyncio with a concurrency semaphore."""
        sem = asyncio.Semaphore(100)
        timeout = 0.5

        async def check_port(port: int) -> Port | None:
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=timeout,
                    )
                except (TimeoutError, OSError):
                    return None

                banner = ""
                if grab_banners:
                    try:
                        if port in (80, 8080, 8000, 8081, 8888, 3000, 5000):
                            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                            await writer.drain()
                        line = await asyncio.wait_for(reader.read(128), timeout=0.3)
                        if line:
                            banner = line.decode(errors="replace").strip().splitlines()[0]
                    except Exception:
                        pass

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

                svc_name = resolve_service_name(port, "tcp")
                service = Service(
                    name=svc_name,
                    product=banner if banner else "",
                    method="native",
                    confidence=3 if banner else 2,
                )
                return Port(number=port, protocol="tcp", state="open", reason="syn-ack", service=service)

        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        open_ports = [p for p in results if p is not None]
        open_ports.sort(key=lambda p: p.number)
        return open_ports
