"""Nmap orchestration with privilege-aware profiles and XML as canonical output."""

from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from netscan.exceptions import NmapNotFoundError, ScanExecutionError
from netscan.models import Host, ScanMetadata, ScanResult
from netscan.parser import parse_nmap_xml
from netscan.risk import score_hosts

LOGGER = logging.getLogger(__name__)


def _load_profiles() -> dict[str, list[str]]:
    """Load built-in scan arguments from packaged YAML profile files."""
    profile_dir = Path(__file__).with_name("profile_data")
    profiles: dict[str, list[str]] = {}
    for path in sorted(profile_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("flags"), str):
            raise RuntimeError(f"Invalid profile file: {path}")
        profiles[str(data.get("name", path.stem))] = shlex.split(data["flags"])
    required = {"discovery", "quick", "full-tcp", "stealth", "service", "udp-top", "os-detect", "vuln", "custom"}
    if set(profiles) != required:
        raise RuntimeError(f"Profile YAML set does not match required profiles: {sorted(set(profiles) ^ required)}")
    return profiles


PROFILES = _load_profiles()


def find_nmap_executable(executable: str = "nmap") -> str | None:
    """Locate the Nmap executable via PATH or standard platform installation paths.

    If found in a standard location not currently on PATH, its parent directory
    is prepended to os.environ['PATH'] so that child processes and wrappers find it.
    """
    found = shutil.which(executable)
    if found is not None:
        return found
    if executable != "nmap" and Path(executable).is_file():
        return str(Path(executable).resolve())

    candidates: list[Path] = []
    if os.name == "nt":
        for env_var in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
            base = os.environ.get(env_var)
            if base:
                candidates.append(Path(base) / "Nmap" / "nmap.exe")
        candidates.extend([
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
            Path(r"C:\Program Files\Nmap\nmap.exe"),
        ])
    else:
        candidates.extend([
            Path("/usr/bin/nmap"),
            Path("/usr/local/bin/nmap"),
            Path("/opt/homebrew/bin/nmap"),
        ])

    for candidate in candidates:
        if candidate.is_file():
            resolved = str(candidate.resolve())
            parent_dir = str(candidate.parent.resolve())
            current_path = os.environ.get("PATH", "")
            if parent_dir.lower() not in current_path.lower():
                os.environ["PATH"] = f"{parent_dir}{os.pathsep}{current_path}"
            return resolved
    return None


class NmapScanner:
    """Run Nmap with timeouts and a raw XML output path."""

    def __init__(self, timeout_seconds: int = 300, executable: str = "nmap") -> None:
        self.timeout_seconds = timeout_seconds
        self.executable = find_nmap_executable(executable)
        if self.executable is None:
            raise NmapNotFoundError(_install_hint())
        self.nmap_version = self._version()
        match = re.match(r"^(\d+)\.(\d+)", self.nmap_version)
        if match is None:
            raise ScanExecutionError(f"Unable to parse installed Nmap version: {self.nmap_version!r}.")
        if (int(match.group(1)), int(match.group(2))) < (7, 80):
            raise ScanExecutionError(f"Nmap 7.80+ is required; found {self.nmap_version}.")

    def _version(self) -> str:
        """Prefer python-nmap's version probe, then fall back to subprocess."""
        try:
            import nmap  # type: ignore[import-untyped]
            version = nmap.PortScanner(nmap_search_path=(self.executable or "nmap",)).nmap_version()
            return ".".join(str(part) for part in version)
        except Exception:  # python-nmap raises its own PortScannerError type across versions.
            try:
                proc = subprocess.run([self.executable or "nmap", "--version"], capture_output=True,
                                      text=True, timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ScanExecutionError(f"Unable to query Nmap version: {exc}") from exc
            if proc.returncode != 0:
                raise ScanExecutionError(f"Nmap version check failed: {proc.stderr.strip()}")
            first = proc.stdout.splitlines()[0] if proc.stdout.splitlines() else "Nmap version unknown"
            return first.replace("Nmap version ", "").split(" ")[0]

    def scan(self, target: str, profile: str, custom_flags: list[str] | None = None,
             allow_vuln: bool = False, engine: str = "auto") -> ScanResult:
        """Scan one in-scope target and parse the XML result."""
        if profile not in PROFILES:
            raise ScanExecutionError(f"Unknown profile {profile!r}.")
        if profile == "vuln" and not allow_vuln:
            raise ScanExecutionError("The vuln profile requires explicit --allow-vuln-scripts acknowledgment.")
        flags = list(PROFILES[profile])
        warnings: list[str] = []
        if profile == "custom":
            flags = validate_custom_flags(custom_flags or [])
        if "-sS" in flags and not _has_privileges():
            flags = ["-sT" if flag == "-sS" else flag for flag in flags]
            warnings.append("Insufficient privileges for SYN scan; downgraded -sS to TCP connect scan (-sT).")
        if "-O" in flags and not _has_privileges():
            flags = [flag for flag in flags if flag != "-O"]
            warnings.append("Insufficient privileges for OS detection; -O was omitted.")
        if engine == "native":
            from netscan.native_scanner import NativeScanner

            return NativeScanner(self.timeout_seconds).scan(
                target, profile, custom_flags=custom_flags, allow_vuln=allow_vuln, engine="native"
            )
        if engine not in {"auto", "wrapper", "subprocess"}:
            raise ScanExecutionError("Engine must be 'auto', 'native', 'wrapper', or 'subprocess'.")
        selected_engine = engine
        if selected_engine == "auto":
            selected_engine = "subprocess" if profile in {"custom", "vuln"} else "wrapper"
        started = datetime.now(timezone.utc)
        command = [self.executable or "nmap", "-n", "-oX", "-", *flags, target]
        LOGGER.info("Starting profile=%s target=%s engine=%s", profile, target, selected_engine)
        begin = time.monotonic()
        if selected_engine == "wrapper":
            xml_output = self._scan_with_wrapper(target, flags)
        else:
            xml_output = self._scan_with_subprocess(target, command)
        elapsed = time.monotonic() - begin
        metadata = ScanMetadata(profile=profile, nmap_version=self.nmap_version, command=command,
            started_at=started.isoformat(), finished_at=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(elapsed, 3), warnings=warnings)
        try:
            result = parse_nmap_xml(xml_output, metadata)
        except ValueError as exc:
            raise ScanExecutionError(str(exc)) from exc
        if not result.hosts:
            result.hosts.append(
                Host(address=target, hostname="", status="down", reason="no-response", ports=[])
            )
        score_hosts(result.hosts)
        LOGGER.info("Completed target=%s hosts=%d duration=%.2fs", target, len(result.hosts), elapsed)
        return result


    def _scan_with_wrapper(self, target: str, flags: list[str]) -> str:
        """Run python-nmap in a bounded child process and return its XML output.

        The wrapper's public scan API does not consistently expose a timeout across
        supported versions. Isolating it in a child process provides an outer timeout
        while preserving the wrapper's XML handling and keeping command arguments out
        of a shell.
        """
        wrapper_script = (
            "import sys\n"
            "import nmap\n"
            "scanner = nmap.PortScanner(nmap_search_path=(sys.argv[1],))\n"
            "scanner.scan(hosts=sys.argv[2], arguments=sys.argv[3])\n"
            "output = scanner.get_nmap_last_output()\n"
            "sys.stdout.write(output if isinstance(output, str) else output.decode())\n"
        )
        command = [sys.executable, "-c", wrapper_script, self.executable or "nmap", target,
                   shlex.join(["-n", *flags])]
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=self.timeout_seconds, check=False, shell=False)
        except subprocess.TimeoutExpired as exc:
            raise ScanExecutionError(
                f"python-nmap wrapper timed out after {self.timeout_seconds}s for {target}."
            ) from exc
        except OSError as exc:
            raise ScanExecutionError(f"Unable to start python-nmap wrapper: {exc}") from exc
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
            raise ScanExecutionError(f"python-nmap failed for {target}: {detail}")
        if "<nmaprun" not in proc.stdout:
            raise ScanExecutionError("python-nmap did not expose valid XML output; use --engine subprocess.")
        return proc.stdout

    def _scan_with_subprocess(self, target: str, command: list[str]) -> str:
        """Run Nmap using argument-list subprocess execution and return XML stdout."""
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_seconds,
                                  check=False, shell=False)
        except subprocess.TimeoutExpired as exc:
            raise ScanExecutionError(f"Nmap timed out after {self.timeout_seconds}s for {target}.") from exc
        except OSError as exc:
            raise ScanExecutionError(f"Could not execute Nmap: {exc}") from exc
        if proc.returncode != 0:
            error = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
            raise ScanExecutionError(f"Nmap failed for {target}: {error}")
        return proc.stdout


def validate_custom_flags(flags: list[str]) -> list[str]:
    """Validate custom Nmap flags against a narrow allowlist and safe value forms."""
    allowed = {"-sT", "-sS", "-sU", "-sV", "-O", "-Pn", "-n", "-F", "-p", "-p-",
               "--top-ports", "--version-intensity", "-T2", "-T3", "-T4", "--reason",
               "--open", "--osscan-limit", "--max-retries", "--host-timeout"}
    value_flags = {"-p", "--top-ports", "--version-intensity", "--max-retries", "--host-timeout"}
    if not flags:
        raise ScanExecutionError("Custom profile requires --custom-flags.")
    result: list[str] = []
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag not in allowed:
            raise ScanExecutionError(f"Custom flag {flag!r} is not allowed by the safety policy.")
        result.append(flag)
        if flag in value_flags:
            i += 1
            if i >= len(flags) or not _safe_flag_value(flag, flags[i]):
                raise ScanExecutionError(f"Invalid or missing value for custom flag {flag}.")
            result.append(flags[i])
        i += 1
    if "--script" in result or any("script" in flag.lower() for flag in result):
        raise ScanExecutionError("NSE scripts are not allowed in custom mode; use the guarded vuln profile.")
    return result


def _safe_flag_value(flag: str, value: str) -> bool:
    """Check that an option value cannot introduce another argument or target."""
    if value.startswith("-") or any(ch in value for ch in "\x00\n\r"):
        return False
    if flag == "-p":
        return all(ch in "0123456789,-TtUuSsCc" for ch in value) and len(value) <= 512
    if flag == "--top-ports":
        return value.isdigit() and 1 <= int(value) <= 65535
    if flag == "--version-intensity":
        return value.isdigit() and 0 <= int(value) <= 9
    if flag == "--max-retries":
        return value.isdigit() and 0 <= int(value) <= 10
    return value.isalnum() or value.endswith("s")


def _has_privileges() -> bool:
    """Return whether this process is elevated enough for privileged scan types."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _install_hint() -> str:
    """Return OS-specific installation guidance for Nmap."""
    return ("Nmap executable was not found. Install it and ensure 'nmap' is on PATH. "
            "Windows: https://nmap.org/download.html | macOS: 'brew install nmap' | "
            "Debian/Ubuntu/Kali: 'sudo apt install nmap' | Fedora: 'sudo dnf install nmap'.")
