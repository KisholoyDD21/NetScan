"""Application settings loaded from YAML and environment variables."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from netscan.exceptions import ConfigurationError


class Settings(BaseSettings):
    """Runtime settings with environment-variable overrides."""

    model_config = SettingsConfigDict(env_prefix="NETSCAN_", extra="ignore")

    default_profile: str = "quick"
    timeout_seconds: int = Field(default=300, ge=10, le=86400)
    output_dir: Path = Path("reports")
    exclude_hosts: list[str] = Field(default_factory=list)
    max_workers: int = Field(default=4, ge=1, le=32)
    rate_delay_seconds: float = Field(default=0.0, ge=0.0, le=10.0)
    cache_dir: Path = Path(".netscan_cache")
    log_dir: Path = Path("logs")
    max_targets: int = Field(default=4096, ge=1, le=65536)


def load_settings(path: Path | None = None) -> Settings:
    """Load YAML settings, then apply environment-variable overrides."""
    values: dict[str, Any] = {}
    if path is not None:
        try:
            parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except OSError as exc:
            raise ConfigurationError(f"Cannot read config {path}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ConfigurationError("Configuration YAML must contain a mapping.")
        values = parsed
    try:
        return Settings(**values)
    except ValidationError as exc:
        raise ConfigurationError(f"Invalid configuration: {exc}") from exc
