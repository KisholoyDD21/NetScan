"""Console and rotating-file logging setup."""

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.logging import RichHandler


class JsonFormatter(logging.Formatter):
    """Format log records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize the core log fields and formatted message."""
        return json.dumps({"time": self.formatTime(record), "level": record.levelname,
                           "logger": record.name, "message": record.getMessage()})


def configure_logging(directory: Path, level: int = logging.INFO, quiet: bool = False) -> None:
    """Replace root handlers with Rich console and rotating JSON logs."""
    directory.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if level == logging.DEBUG else level)
    console_level = logging.ERROR if quiet else level
    console = RichHandler(rich_tracebacks=True, show_path=False, markup=True)
    console.setLevel(console_level)
    root.addHandler(console)
    file_handler = RotatingFileHandler(directory / "netscan.log", maxBytes=2_000_000, backupCount=3,
                                       encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JsonFormatter())
    root.addHandler(file_handler)
