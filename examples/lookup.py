#!/usr/bin/env python3
"""Example CLI tool for domain squatting analysis.

This script demonstrates how to use the Have I Been Squatted Python SDK
to analyze a domain for potential squatting attempts.

Usage:
    export HIBS_API_KEY="ak_your_api_key_here"
    python lookup.py example.com

Requirements:
    - API key set in HIBS_API_KEY environment variable (or pass --api-key)
    - haveibeensquatted package installed
"""

import argparse
import asyncio
import logging
import os

from haveibeensquatted import (
    HaveIBeenSquatted,
    HTTPError,
    MetaKind,
    Operation,
    RateLimitError,
    URLError,
)

# Progress data minimum length (current, total)
MIN_PROGRESS_DATA_LENGTH = 2


async def analyze_squatting(domain: str, api_key: str) -> None:
    """Analyze a domain for squatting attempts.

    Args:
        domain: The domain to analyze
        api_key: API key for API authentication
    """
    logging.info("analyzing %s for squatting attempts", domain)

    # Initialize client
    client = HaveIBeenSquatted(api_key)

    # Track progress and results
    total_permutations = 0
    current_permutation = 0
    results_found = 0

    try:
        async for message in client.squat(domain):
            if message.op == Operation.META:
                if message.data and message.data.kind == MetaKind.PROGRESS:
                    progress_data = message.data.data
                    if (
                        isinstance(progress_data, list)
                        and len(progress_data) >= MIN_PROGRESS_DATA_LENGTH
                    ):
                        current_permutation, total_permutations = progress_data
                        logging.info(
                            "progress %d/%d permutations", current_permutation, total_permutations
                        )

                elif message.data and message.data.kind == MetaKind.DONE:
                    logging.info("analysis complete")
                    break

                elif message.data and message.data.kind == MetaKind.ERROR:
                    error_msg = message.data.data
                    logging.error("%s", error_msg)
                    break

            elif message.op == Operation.IP_ENUMERATION:
                if message.permutation:
                    results_found += 1
                    perm_domain = message.permutation.domain.fqdn
                    perm_kind = message.permutation.kind.value
                    logging.info("registered permutation: %s (%s)", perm_domain, perm_kind)

            elif message.op == Operation.GEO_IP:
                if message.data and message.permutation:
                    perm_domain = message.permutation.domain.fqdn
                    ip = message.data.ip
                    country = message.data.country.iso_code if message.data.country else None
                    org = message.data.asn.organization if message.data.asn else None
                    logging.info("%s hosted at %s (%s) by %s", perm_domain, ip, country, org)

            elif message.op == Operation.CLASSIFICATION and message.data and message.permutation:
                perm_domain = message.permutation.domain.fqdn
                classification = message.data
                logging.info(
                    "%s classification: legitimate=%.2f phishing=%.2f parked=%.2f",
                    perm_domain,
                    classification.legitimate,
                    classification.phishing,
                    classification.parked,
                )

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
        return

    percentage = (results_found / total_permutations) * 100 if total_permutations else 0.0
    logging.info(
        "summary: permutations=%d registered=%d registration_rate=%.1f%%",
        total_permutations,
        results_found,
        percentage,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze a domain for squatting permutations")
    parser.add_argument("domain", help="domain name to analyze")
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


def main() -> None:
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

    domain = args.domain.strip()
    if not domain:
        logging.error("domain cannot be empty")
        raise SystemExit(1)

    asyncio.run(analyze_squatting(domain, api_key))


if __name__ == "__main__":
    main()
