#!/usr/bin/env python3
"""Example CLI tool for certificate transparency search."""

import argparse
import asyncio
import logging
import os

from haveibeensquatted import (
    HaveIBeenSquatted,
    HTTPError,
    HydratedOccurrenceResult,
    OccurrenceRec,
    RateLimitError,
    URLError,
)


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


def should_log_ct_access_note(exc: Exception) -> bool:
    if not isinstance(exc, HTTPError):
        return False
    return str(exc).startswith(("HTTP 401:", "HTTP 403:"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Search certificate transparency logs")
    parser.add_argument("--pattern", help="search pattern (regex)")
    parser.add_argument("--kind", default="regex", help="search kind (default: regex)")
    parser.add_argument("--limit", type=int, default=10, help="max results (default: 10)")
    parser.add_argument("--field", default=None, help="field to search (optional)")
    parser.add_argument("--include-precert", action="store_true", help="include precerts")
    parser.add_argument(
        "--fqdn",
        action="append",
        default=[],
        help="exact fqdn lookup (repeatable)",
    )
    parser.add_argument(
        "--hydrate",
        action="store_true",
        help="hydrate first result occurrences",
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

    client = HaveIBeenSquatted(api_key)

    try:
        if args.fqdn:
            results = await client.ct_search_domains(
                args.fqdn, include_precert=args.include_precert
            )
            logging.info("found %d results", len(results))
        else:
            if not args.pattern:
                logging.error("--pattern is required when not using --fqdn")
                raise SystemExit(1)
            response = await client.ct_search(
                args.pattern,
                kind=args.kind,
                limit=args.limit,
                field=args.field,
                include_precert=args.include_precert,
            )
            results = response.results
            logging.info("found %d results (has_more=%s)", len(results), response.has_more)

        for result in results:
            logging.info(
                "result: %s (precert=%s occurrences=%s)",
                result.name,
                result.is_precert,
                result.occurrences_count,
            )

        if args.hydrate and results and results[0].occurrences:
            occs: list[tuple[int, int]] = []
            for occ in results[0].occurrences[:5]:
                occ_rec: OccurrenceRec
                occ_rec = occ.occ if isinstance(occ, HydratedOccurrenceResult) else occ
                occs.append((occ_rec.log_id, occ_rec.index))
            hydrated = await client.ct_hydrate(occs)
            logging.info("hydrated %d occurrences", len(hydrated))
    except Exception as exc:
        log_common_error(exc)
        if should_log_ct_access_note(exc):
            logging.info("note: CT endpoints require a key with CT access enabled")
        raise SystemExit(1) from exc


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
