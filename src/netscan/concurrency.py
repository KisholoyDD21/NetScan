"""Bounded asynchronous orchestration around blocking Nmap processes."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")


async def run_bounded(items: list[str], worker: Callable[[str], T], max_workers: int,
                      rate_delay_seconds: float = 0.0,
                      on_complete: Callable[[str, T | Exception], None] | None = None) -> list[T | Exception]:
    """Run blocking workers in a bounded pool and preserve input order."""
    loop = asyncio.get_running_loop()
    semaphore = asyncio.Semaphore(max_workers)
    results: list[T | Exception | None] = [None] * len(items)
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="netscan") as pool:
        async def one(index: int, item: str) -> None:
            async with semaphore:
                if rate_delay_seconds:
                    await asyncio.sleep(rate_delay_seconds)
                try:
                    result = await loop.run_in_executor(pool, worker, item)
                    results[index] = result
                except Exception as exc:
                    results[index] = exc
                if on_complete is not None and results[index] is not None:
                    on_complete(item, results[index])
        await asyncio.gather(*(one(index, item) for index, item in enumerate(items)))
    return [value for value in results if value is not None]
