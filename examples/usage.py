#!/usr/bin/env python3
"""Example CLI tool for usage metrics."""

import argparse
import asyncio
import logging
import os

from haveibeensquatted import HaveIBeenSquatted


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch API usage metrics")
    parser.add_argument("--minutes", type=int, default=1440, help="period in minutes")
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=os.getenv("HIBS_API_KEY"),
        help="API key (defaults to HIBS_API_KEY env var)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="logging level",
    )
    return parser.parse_args()


async def main_async() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if not args.api_key:
        logging.error("HIBS_API_KEY not set; set the environment variable or pass --api-key")
        raise SystemExit(1)

    client = HaveIBeenSquatted(args.api_key)
    usage = await client.usage(minutes=args.minutes)

    logging.info("period: %s -> %s", usage.period.start, usage.period.end)
    logging.info(
        "totals: lookup=%d ct=%d total=%d",
        usage.totals.lookup_requests,
        usage.totals.ct_requests,
        usage.totals.total_requests,
    )


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
