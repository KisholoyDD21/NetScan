"""Scanner command validation and execution tests; no Nmap binary is required."""

import subprocess

import pytest

from netscan.exceptions import NmapNotFoundError, ScanExecutionError
from netscan.scanner import NmapScanner, validate_custom_flags


def test_custom_flags_accept_safe_values() -> None:
    assert validate_custom_flags(["-sV", "--top-ports", "20"]) == ["-sV", "--top-ports", "20"]


@pytest.mark.parametrize("flags", [["--script", "vuln"], ["-oN", "out.txt"], [";", "whoami"], ["--top-ports", "999999"]])
def test_custom_flags_reject_unsafe_values(flags: list[str]) -> None:
    with pytest.raises(ScanExecutionError):
        validate_custom_flags(flags)


def test_missing_nmap_has_install_hint(monkeypatch) -> None:
    monkeypatch.setattr("netscan.scanner.find_nmap_executable", lambda *_: None)
    with pytest.raises(NmapNotFoundError, match="nmap.org/download"):
        NmapScanner()


def test_scan_runs_list_command_and_parses_xml(monkeypatch, sample_xml: str) -> None:
    scanner = object.__new__(NmapScanner)
    scanner.timeout_seconds = 20
    scanner.executable = "/usr/bin/nmap"
    scanner.nmap_version = "7.94"
    calls: list[list[str]] = []
    def fake_run(command, **kwargs):
        calls.append(command)
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(command, 0, sample_xml, "")
    monkeypatch.setattr("netscan.scanner.subprocess.run", fake_run)
    result = scanner.scan("127.0.0.1", "quick", engine="subprocess")
    assert result.hosts[0].address == "127.0.0.1"
    assert calls[0][:4] == ["/usr/bin/nmap", "-n", "-oX", "-"]


def test_scan_timeout_is_reported(monkeypatch) -> None:
    scanner = object.__new__(NmapScanner)
    scanner.timeout_seconds = 1
    scanner.executable = "nmap"
    scanner.nmap_version = "7.94"
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("nmap", 1)
    monkeypatch.setattr("netscan.scanner.subprocess.run", timeout)
    with pytest.raises(ScanExecutionError, match="timed out"):
        scanner.scan("127.0.0.1", "quick", engine="subprocess")


def test_vuln_profile_requires_acknowledgment() -> None:
    scanner = object.__new__(NmapScanner)
    scanner.timeout_seconds, scanner.executable, scanner.nmap_version = 5, "nmap", "7.94"
    with pytest.raises(ScanExecutionError, match="explicit"):
        scanner.scan("127.0.0.1", "vuln")



def test_wrapper_engine_uses_python_nmap_in_timed_child(monkeypatch, sample_xml: str) -> None:
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        assert kwargs["timeout"] == 15
        assert kwargs["shell"] is False
        assert command[1] == "-c"
        assert "nmap.PortScanner" in command[2]
        assert command[3:] == ["/usr/bin/nmap", "127.0.0.1", "-n -sT --top-ports 100"]
        return subprocess.CompletedProcess(command, 0, sample_xml, "")

    monkeypatch.setattr("netscan.scanner.subprocess.run", fake_run)
    scanner = object.__new__(NmapScanner)
    scanner.timeout_seconds, scanner.executable, scanner.nmap_version = 15, "/usr/bin/nmap", "7.94"
    result = scanner.scan("127.0.0.1", "quick", engine="wrapper")
    assert result.hosts[0].address == "127.0.0.1"
    assert calls


def test_nonzero_nmap_exit_is_reported(monkeypatch) -> None:
    scanner = object.__new__(NmapScanner)
    scanner.timeout_seconds, scanner.executable, scanner.nmap_version = 5, "nmap", "7.94"
    def fail(command, **kwargs):
        return subprocess.CompletedProcess(command, 2, "", "permission denied")
    monkeypatch.setattr("netscan.scanner.subprocess.run", fail)
    with pytest.raises(ScanExecutionError, match="permission denied"):
        scanner.scan("127.0.0.1", "quick", engine="subprocess")



def test_rejects_old_nmap_version(monkeypatch) -> None:
    import sys
    from types import SimpleNamespace
    class FakePortScanner:
        def __init__(self, nmap_search_path):
            pass
        def nmap_version(self):
            return (7, 79)
    monkeypatch.setitem(sys.modules, "nmap", SimpleNamespace(PortScanner=FakePortScanner))
    monkeypatch.setattr("netscan.scanner.shutil.which", lambda _: "/usr/bin/nmap")
    with pytest.raises(ScanExecutionError, match=r"7.80\+"):
        NmapScanner()


def test_find_nmap_executable_from_path(monkeypatch) -> None:
    from netscan.scanner import find_nmap_executable

    monkeypatch.setattr("netscan.scanner.shutil.which", lambda exe: f"/opt/bin/{exe}")
    assert find_nmap_executable("nmap") == "/opt/bin/nmap"


def test_find_nmap_executable_from_candidates(monkeypatch, tmp_path) -> None:
    from netscan.scanner import find_nmap_executable

    fake_nmap = tmp_path / "nmap.exe"
    fake_nmap.write_text("fake binary")

    monkeypatch.setattr("netscan.scanner.shutil.which", lambda _: None)
    monkeypatch.setattr("netscan.scanner.os.name", "nt")
    monkeypatch.setenv("ProgramFiles", str(tmp_path.parent))
    monkeypatch.setattr("netscan.scanner.Path.is_file", lambda p: str(p).endswith("nmap.exe"))

    found = find_nmap_executable("nmap")
    assert found is not None
    assert "nmap.exe" in found.lower()


def test_native_scanner_quick(monkeypatch) -> None:
    from netscan.native_scanner import NativeScanner

    scanner = NativeScanner()
    # Mock _scan_ports_async to return open port 135
    async def fake_scan_ports(host, ports, grab_banners=False):
        from netscan.models import Port, Service
        return [Port(number=135, protocol="tcp", state="open", reason="syn-ack", service=Service(name="msrpc"))]

    monkeypatch.setattr(scanner, "_scan_ports_async", fake_scan_ports)
    result = scanner.scan("127.0.0.1", "quick")
    assert len(result.hosts) == 1
    assert result.hosts[0].status == "up"
    assert len(result.hosts[0].ports) == 1
    assert result.hosts[0].ports[0].number == 135
    assert result.metadata.nmap_version == "native-python"


def test_native_scanner_vuln_requires_ack() -> None:
    from netscan.native_scanner import NativeScanner

    scanner = NativeScanner()
    with pytest.raises(ScanExecutionError, match="explicit"):
        scanner.scan("127.0.0.1", "vuln", allow_vuln=False)


def test_native_scanner_profiles_and_custom(monkeypatch) -> None:
    from netscan.native_scanner import NativeScanner

    scanner = NativeScanner()
    async def fake_scan_ports(host, ports, grab_banners=False):
        return []

    monkeypatch.setattr(scanner, "_scan_ports_async", fake_scan_ports)
    res_disc = scanner.scan("127.0.0.1", "discovery")
    assert res_disc.hosts[0].status == "up"

    res_custom = scanner.scan("127.0.0.1", "custom", custom_flags=["-p", "80,443"])
    assert res_custom.metadata.profile == "custom"

