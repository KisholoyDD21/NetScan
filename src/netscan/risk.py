"""Explainable heuristic risk scoring; scores are not CVE severity estimates."""

from netscan.models import Host

RISKY_PORTS: dict[int, int] = {
    21: 12, 22: 3, 23: 18, 25: 5, 445: 18, 1433: 14, 3306: 12,
    3389: 14, 5432: 10, 5900: 12, 6379: 18, 9200: 15, 27017: 15,
}


def score_host(host: Host) -> tuple[int, str]:
    """Return a capped 0–100 heuristic score and risk bucket."""
    score = 0
    open_ports = [port for port in host.ports if port.state == "open"]
    for port in open_ports:
        score += RISKY_PORTS.get(port.number, 2)
        if port.service.product:
            score += 2
        if port.service.version:
            score += 2
        if port.service.name.lower() in {"telnet", "ftp", "redis", "mongodb", "ms-sql-s"}:
            score += 8
        if port.scripts:
            score += min(10, 2 * len(port.scripts))
    score = min(100, score)
    level = "Low" if score < 20 else "Medium" if score < 45 else "High" if score < 70 else "Critical"
    host.risk_score, host.risk_level = score, level
    return score, level


def score_hosts(hosts: list[Host]) -> None:
    """Update risk scores in place for all hosts."""
    for host in hosts:
        score_host(host)
