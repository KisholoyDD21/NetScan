"""Configuration loading tests."""

from pathlib import Path

import pytest

from netscan.config import load_settings
from netscan.exceptions import ConfigurationError


def test_defaults_are_valid() -> None:
    settings = load_settings()
    assert settings.default_profile == "quick"
    assert settings.max_workers == 4


def test_yaml_values_load(tmp_path: Path) -> None:
    path = tmp_path / "netscan.yaml"
    path.write_text("default_profile: discovery\nmax_workers: 2\noutput_dir: artifacts\n", encoding="utf-8")
    settings = load_settings(path)
    assert settings.default_profile == "discovery"
    assert settings.max_workers == 2
    assert settings.output_dir == Path("artifacts")


def test_invalid_yaml_mapping_fails(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- not a mapping\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="mapping"):
        load_settings(path)


def test_invalid_setting_fails(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("max_workers: 1000\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Invalid configuration"):
        load_settings(path)
