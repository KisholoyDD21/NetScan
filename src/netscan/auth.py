"""Authorization gate, scope parsing, and safe target normalization."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import yaml

from netscan.exceptions import AuthorizationError, TargetValidationError


def normalize_target(value: str) -> str:
    """Normalize an IP, network, or DNS hostname without resolving it."""
    target = value.strip().rstrip(".")
    if not target or any(char in target for char in "\\\x00\n\r\t "):
        raise TargetValidationError(f"Invalid target: {value!r}")
    try:
        return str(ipaddress.ip_network(target, strict=False)) if "/" in target else str(ipaddress.ip_address(target))
    except ValueError:
        if "/" in target:
            raise TargetValidationError(f"Invalid IP network: {value!r}")
    if len(target) > 253 or not all(
        label and len(label) <= 63 and label[0] != "-" and label[-1] != "-"
        and all(ch.isalnum() or ch == "-" for ch in label)
        for label in target.split(".")
    ):
        raise TargetValidationError(f"Invalid hostname: {value!r}")
    return target.lower()


def parse_targets(targets: str | None, targets_file: Path | None, max_targets: int,
                  acknowledge_large: bool = False) -> list[str]:
    """Parse comma-separated or file-based targets; expand manageable CIDRs."""
    raw: list[str] = []
    if targets:
        raw.extend(item.strip() for item in targets.split(",") if item.strip())
    if targets_file:
        try:
            raw.extend(line.strip() for line in targets_file.read_text(encoding="utf-8").splitlines()
                        if line.strip() and not line.lstrip().startswith("#"))
        except OSError as exc:
            raise TargetValidationError(f"Cannot read targets file: {exc}") from exc
    if not raw:
        raise TargetValidationError("Provide --targets or --targets-file.")
    normalized: list[str] = []
    effective_max = 65536 if acknowledge_large else max_targets
    for item in raw:
        target = normalize_target(item)
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            size = network.num_addresses
            if size > max_targets and not acknowledge_large:
                raise TargetValidationError(
                    f"Network {target} contains {size:,} addresses; use a smaller scope or --i-know-this-is-big."
                )
            if size > effective_max:
                raise TargetValidationError(
                    f"Target expansion exceeds the hard safety cap of {effective_max:,} addresses; narrow the CIDR."
                )
            candidates: Iterable[object] = network.hosts()
            normalized.extend(str(ip) for ip in candidates)
        else:
            normalized.append(target)
        if len(set(normalized)) > effective_max:
            raise TargetValidationError(f"Target list exceeds limit ({effective_max}).")
    return list(dict.fromkeys(normalized))


class ScopeAuthorizer:
    """Validate explicit authorization and confirm every target is in scope."""

    def __init__(self, scope_file: Path) -> None:
        self.scope_file = scope_file
        self.targets: list[str] = []
        self.expires_at: datetime | None = None
        self.owner: str = "unspecified"
        self._load()

    def _load(self) -> None:
        """Read a YAML scope declaration and validate its structure."""
        try:
            data = yaml.safe_load(self.scope_file.read_text(encoding="utf-8"))
        except OSError as exc:
            raise AuthorizationError(f"Cannot read scope file {self.scope_file}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise AuthorizationError(f"Scope file is invalid YAML: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("targets"), list) or not data["targets"]:
            raise AuthorizationError("Scope file must define a non-empty 'targets' list.")
        try:
            self.targets = [normalize_target(str(item)) for item in data["targets"]]
        except TargetValidationError as exc:
            raise AuthorizationError(f"Scope file contains an invalid target: {exc}") from exc
        self.owner = str(data.get("owner", "unspecified"))
        expiry = data.get("expires_at")
        if expiry:
            try:
                self.expires_at = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
                if self.expires_at.tzinfo is None:
                    self.expires_at = self.expires_at.replace(tzinfo=UTC)
            except ValueError as exc:
                raise AuthorizationError("expires_at must be ISO-8601 (for example 2027-01-31T23:59:00Z).") from exc

    def _suggest_target(self, target: str) -> str | None:
        """Find the closest authorized target to help catch typos."""
        import difflib

        matches = difflib.get_close_matches(target, self.targets, n=1, cutoff=0.6)
        if matches:
            return matches[0]
        try:
            target_parts = target.split(".")
            if len(target_parts) == 4:
                prefix = ".".join(target_parts[:3])
                for allowed in self.targets:
                    if allowed.startswith(prefix):
                        return allowed
        except Exception:
            pass
        return None

    def authorize(self, explicit_flag: bool, targets: list[str]) -> None:
        """Require the flag, a current scope file, and complete target coverage."""
        if not explicit_flag:
            raise AuthorizationError("Scanning is disabled unless --authorized is explicitly supplied.")
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            raise AuthorizationError("Authorization scope has expired.")
        for target in targets:
            if not any(_covered(target, allowed) for allowed in self.targets):
                suggestion = self._suggest_target(target)
                hint = f" Did you mean '{suggestion}'?" if suggestion else ""
                raise AuthorizationError(f"Target {target} is not covered by scope file {self.scope_file}.{hint}")


def detect_local_ips() -> list[str]:
    """Detect active local network IPv4 addresses on the host system."""
    import socket

    ips = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        _, _, host_ips = socket.gethostbyname_ex(hostname)
        for ip in host_ips:
            if not ip.startswith("169.254.") and ip != "127.0.0.1":
                ips.add(ip)
    except OSError:
        pass
    return sorted(ips)


def add_targets_to_scope(scope_path: Path, new_targets: list[str], owner: str = "Local lab owner") -> list[str]:
    """Add new validated targets to a YAML scope file, preserving existing fields."""
    normalized_new: list[str] = [normalize_target(t) for t in new_targets]
    data: dict[str, object] = {}
    if scope_path.is_file():
        try:
            loaded = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            pass

    existing_raw = data.get("targets", [])
    existing: list[str] = [str(x) for x in existing_raw] if isinstance(existing_raw, list) else []

    added: list[str] = []
    for target in normalized_new:
        if target not in existing:
            existing.append(target)
            added.append(target)

    data["targets"] = existing
    if "owner" not in data:
        data["owner"] = owner
    if "expires_at" not in data:
        data["expires_at"] = "2028-12-31T23:59:00Z"

    scope_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return added


def _covered(target: str, allowed: str) -> bool:
    """Return whether an IP/hostname target is covered by a scope entry."""
    if target == allowed:
        return True
    try:
        t_ip = ipaddress.ip_address(target)
        a_net = ipaddress.ip_network(allowed, strict=False)
        return t_ip.version == a_net.version and t_ip in a_net
    except ValueError:
        try:
            target_network = ipaddress.ip_network(target, strict=False)
            allowed_network = ipaddress.ip_network(allowed, strict=False)
            return target_network.version == allowed_network.version and target_network.subnet_of(allowed_network)
        except ValueError:
            return False
