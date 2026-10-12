"""Small TTL cache for previously scanned host results."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from netscan.models import CveCandidate, Host, Port, ScriptOutput, Service


class ScanCache:
    """Persist host results by target and profile, with explicit TTL checks."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _path(self, target: str, profile: str) -> Path:
        """Compute a stable cache path without exposing target strings in filenames."""
        digest = hashlib.sha256(f"{target}|{profile}".encode()).hexdigest()
        return self.directory / f"{digest}.json"

    def get(self, target: str, profile: str, ttl_seconds: int) -> Host | None:
        """Return a cached host while its entry is fresh; otherwise return None."""
        if ttl_seconds <= 0:
            return None
        path = self._path(target, profile)
        try:
            raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - float(raw["cached_at"]) > ttl_seconds:
                return None
            data = raw["host"]
            ports = [Port(**{**p, "service": Service(**p.get("service", {})),
                             "scripts": [ScriptOutput(**s) for s in p.get("scripts", [])]})
                     for p in data.get("ports", [])]
            candidates = [CveCandidate(**item) for item in data.get("cve_candidates", [])]
            return Host(**{**data, "ports": ports, "cve_candidates": candidates})
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def put(self, target: str, profile: str, host: Host) -> None:
        """Write one host result atomically to disk."""
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self._path(target, profile)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps({"cached_at": time.time(), "host": _host_dict(host)}, indent=2), encoding="utf-8")
        temp.replace(path)


def _host_dict(host: Host) -> dict[str, Any]:
    """Convert a host model to JSON-compatible primitives."""
    from dataclasses import asdict
    return asdict(host)
