"""Authorization and target validation tests."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from netscan.auth import ScopeAuthorizer, normalize_target, parse_targets
from netscan.exceptions import AuthorizationError, TargetValidationError


def test_normalizes_ip_network_hostname() -> None:
    assert normalize_target("127.0.0.1") == "127.0.0.1"
    assert normalize_target("192.168.1.4/24") == "192.168.1.0/24"
    assert normalize_target("LAB.Example.COM.") == "lab.example.com"


@pytest.mark.parametrize("value", ["", "bad host", "-bad.example", "127.0.0.1/99", "a\\b"])
def test_rejects_invalid_target(value: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_target(value)


def test_parse_target_list_and_file(tmp_path: Path) -> None:
    file = tmp_path / "targets.txt"
    file.write_text("# comment\n192.0.2.2\nlocalhost\n", encoding="utf-8")
    assert parse_targets("127.0.0.1,LOCALHOST", file, max_targets=10) == ["127.0.0.1", "localhost", "192.0.2.2"]


def test_cidr_cap_requires_acknowledgment() -> None:
    with pytest.raises(TargetValidationError, match="i-know-this-is-big"):
        parse_targets("192.0.2.0/24", None, max_targets=10)
    assert len(parse_targets("192.0.2.0/24", None, max_targets=10, acknowledge_large=True)) == 254


def test_authorizer_enforces_flag_and_scope(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text(yaml.safe_dump({"owner": "lab", "targets": ["192.168.56.0/24", "localhost"]}), encoding="utf-8")
    auth = ScopeAuthorizer(scope)
    auth.authorize(True, ["192.168.56.8", "localhost"])
    with pytest.raises(AuthorizationError, match="--authorized"):
        auth.authorize(False, ["localhost"])
    with pytest.raises(AuthorizationError, match="not covered"):
        auth.authorize(True, ["198.51.100.2"])


def test_authorizer_rejects_expired_and_invalid_scope(tmp_path: Path) -> None:
    scope = tmp_path / "expired.yaml"
    scope.write_text(yaml.safe_dump({"expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
                                     "targets": ["127.0.0.1"]}), encoding="utf-8")
    with pytest.raises(AuthorizationError, match="expired"):
        ScopeAuthorizer(scope).authorize(True, ["127.0.0.1"])
    scope.write_text("targets: []\n", encoding="utf-8")
    with pytest.raises(AuthorizationError, match="non-empty"):
        ScopeAuthorizer(scope)
    scope.write_text("targets: [\n", encoding="utf-8")
    with pytest.raises(AuthorizationError, match="invalid YAML"):
        ScopeAuthorizer(scope)


def test_network_scope_contains_subnetwork(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text("targets:\n  - 10.0.0.0/8\n", encoding="utf-8")
    ScopeAuthorizer(scope).authorize(True, ["10.1.2.0/24"])



def test_rejects_target_file_and_cidr_over_hard_limit(tmp_path: Path) -> None:
    with pytest.raises(TargetValidationError, match="Cannot read targets file"):
        parse_targets(None, tmp_path / "missing.txt", max_targets=10)
    with pytest.raises(TargetValidationError, match="hard safety cap"):
        parse_targets("10.0.0.0/15", None, max_targets=10, acknowledge_large=True)


def test_scope_rejects_invalid_target_and_expiry_format(tmp_path: Path) -> None:
    scope = tmp_path / "invalid.yaml"
    scope.write_text("targets:\n  - 'bad host'\n", encoding="utf-8")
    with pytest.raises(AuthorizationError, match="invalid target"):
        ScopeAuthorizer(scope)
    scope.write_text("targets:\n  - 127.0.0.1\nexpires_at: definitely-not-a-date\n", encoding="utf-8")
    with pytest.raises(AuthorizationError, match="ISO-8601"):
        ScopeAuthorizer(scope)


def test_authorizer_suggests_typo_correction(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text("targets:\n  - 192.168.23.1\n", encoding="utf-8")
    auth = ScopeAuthorizer(scope)
    with pytest.raises(AuthorizationError, match="Did you mean '192.168.23.1'"):
        auth.authorize(True, ["194.168.23.1"])


def test_detect_local_ips_and_add_to_scope(tmp_path: Path) -> None:
    from netscan.auth import add_targets_to_scope, detect_local_ips

    ips = detect_local_ips()
    assert "127.0.0.1" in ips

    scope = tmp_path / "scope.yaml"
    added = add_targets_to_scope(scope, ["192.168.1.100"])
    assert added == ["192.168.1.100"]

    # Adding again should be idempotent
    added_again = add_targets_to_scope(scope, ["192.168.1.100"])
    assert added_again == []

