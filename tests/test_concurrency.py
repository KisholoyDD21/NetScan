"""Tests for bounded asynchronous orchestration."""

import asyncio

from netscan.concurrency import run_bounded


def test_run_bounded_preserves_order_and_calls_callback() -> None:
    seen: list[str] = []
    def worker(value: str) -> str:
        return value.upper()
    result = asyncio.run(run_bounded(["a", "b", "c"], worker, 2, on_complete=lambda item, _: seen.append(item)))
    assert result == ["A", "B", "C"]
    assert sorted(seen) == ["a", "b", "c"]


def test_run_bounded_returns_worker_errors() -> None:
    def worker(value: str) -> str:
        if value == "bad":
            raise ValueError("example")
        return value
    result = asyncio.run(run_bounded(["ok", "bad"], worker, 1))
    assert result[0] == "ok"
    assert isinstance(result[1], ValueError)
