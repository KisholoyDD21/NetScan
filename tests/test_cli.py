"""CLI safety checks that do not require Nmap."""

from typer.testing import CliRunner

from netscan.cli import app

runner = CliRunner()


def test_scan_requires_authorization() -> None:
    result = runner.invoke(app, ["scan", "--targets", "127.0.0.1"])
    assert result.exit_code == 3
    assert "Authorization required" in result.stdout


def test_profiles_command() -> None:
    result = runner.invoke(app, ["profiles"])
    assert result.exit_code == 0
    assert "full-tcp" in result.stdout



def test_invalid_report_is_usage_error_before_scan() -> None:
    result = runner.invoke(app, ["scan", "--targets", "127.0.0.1", "--scope-file", "examples/scope.example.yaml",
                                 "--authorized", "--report", "bogus"])
    assert result.exit_code == 2
    assert "Unsupported" in result.stdout


def test_custom_flags_are_validated_before_scan() -> None:
    result = runner.invoke(app, ["scan", "--targets", "127.0.0.1", "--scope-file", "examples/scope.example.yaml",
                                 "--authorized", "--profile", "custom", "--custom-flags", "--script vuln"])
    assert result.exit_code == 2
    assert "Invalid custom flags" in result.stdout


def test_invalid_engine_is_rejected() -> None:
    result = runner.invoke(app, ["scan", "--targets", "127.0.0.1", "--scope-file", "examples/scope.example.yaml",
                                 "--authorized", "--engine", "invalid-engine"])
    assert result.exit_code == 2
    assert "--engine must be" in result.stdout


def test_scope_cli_commands(tmp_path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text("targets:\n  - 127.0.0.1\nowner: Test Lab\n", encoding="utf-8")

    # List
    res_list = runner.invoke(app, ["scope", "list", "--scope-file", str(scope)])
    assert res_list.exit_code == 0
    assert "127.0.0.1" in res_list.stdout
    assert "Test Lab" in res_list.stdout

    # Add
    res_add = runner.invoke(app, ["scope", "add", "192.168.1.55", "--scope-file", str(scope)])
    assert res_add.exit_code == 0
    assert "Successfully added" in res_add.stdout

    # Local
    res_local = runner.invoke(app, ["scope", "local", "--scope-file", str(scope), "--yes"])
    assert res_local.exit_code == 0
    assert "Discovered local machine interfaces" in res_local.stdout


