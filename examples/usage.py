#!/usr/bin/env python3
"""Example CLI tool for usage metrics."""

import argparse
import asyncio
import logging
import os

from haveibeensquatted import HaveIBeenSquatted, HTTPError, RateLimitError, URLError


def resolve_api_key(explicit_api_key: str | None) -> str | None:
    if explicit_api_key:
        return explicit_api_key
    return os.getenv("HIBS_API_KEY")


def configure_logging(log_level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def log_common_error(exc: Exception) -> None:
    if isinstance(exc, RateLimitError):
        logging.error("rate limited (retry_after=%s limit=%s)", exc.retry_after, exc.limit)
        return
    if isinstance(exc, HTTPError):
        logging.error("request failed: %s", exc)
        return
    if isinstance(exc, URLError):
        logging.error("network error: %s", exc)
        return
    logging.error("unexpected error: %s", exc)


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
    configure_logging(args.log_level)

    api_key = resolve_api_key(args.api_key)
    if not api_key:
        logging.error("HIBS_API_KEY not set; set the environment variable or pass --api-key")
        raise SystemExit(1)

    try:
        client = HaveIBeenSquatted(api_key)
        usage = await client.usage(minutes=args.minutes)
    except Exception as exc:
        log_common_error(exc)
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
