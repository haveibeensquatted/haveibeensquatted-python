#!/usr/bin/env python3
"""Example CLI tool for usage metrics."""

import argparse
import asyncio
import logging
import os

from haveibeensquatted import HaveIBeenSquatted, HTTPError, RateLimitError, URLError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch API usage metrics")
    parser.add_argument(
        "--minutes",
        type=int,
        default=1440,
        help="period in minutes (API uses the `t` query parameter internally, minimum 60)",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
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

    api_key = args.api_key or os.getenv("HIBS_API_KEY")
    if not api_key:
        logging.error("HIBS_API_KEY not set; set the environment variable or pass --api-key")
        raise SystemExit(1)

    try:
        client = HaveIBeenSquatted(api_key)
        usage = await client.usage(minutes=args.minutes)
    except Exception as exc:
        match exc:
            case RateLimitError():
                logging.error("rate limited (retry_after=%s limit=%s)", exc.retry_after, exc.limit)
            case HTTPError():
                logging.error("request failed: %s", exc)
            case URLError():
                logging.error("network error: %s", exc)
            case _:
                logging.error("unexpected error: %s", exc)
        raise SystemExit(1) from exc

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
