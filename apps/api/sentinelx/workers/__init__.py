"""Standalone job worker entrypoint.

Usage:
    python -m sentinelx.workers            # single worker
    python -m sentinelx.workers --count 3 # three worker loops
"""
from __future__ import annotations

import argparse
import asyncio
import logging

from ..db import init_db


async def _run(count: int) -> None:
    init_db()
    from . import worker_loop  # noqa: F401
    from ..services.jobs import worker_loop

    loops = [asyncio.create_task(worker_loop(interval=2.0)) for _ in range(count)]
    await asyncio.gather(*loops)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(description="SENTINEL X job worker")
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    asyncio.run(_run(args.count))


if __name__ == "__main__":
    main()
