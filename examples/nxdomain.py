#!/usr/bin/env python3
"""Example CLI tool for unregistered domain analysis.

This script demonstrates how to use the Have I Been Squatted Python SDK
to find unregistered domain permutations (NXDOMAIN results).

Usage:
    export HIBS_API_KEY="ak_your_api_key_here"
    python nxdomain.py example.com

Requirements:
    - API key set in HIBS_API_KEY environment variable (or pass --api-key)
    - haveibeensquatted package installed
"""

import argparse
import asyncio
import logging
import os

from haveibeensquatted import HaveIBeenSquatted, MetaKind, Operation

# Progress data minimum length (current, total)
MIN_PROGRESS_DATA_LENGTH = 2


async def check_nxdomains(domain: str, api_key: str) -> None:
    """Check for unregistered domain permutations.

    Args:
        domain: The domain to analyze
        api_key: API key for API authentication
    """
    logging.info("checking %s for unregistered permutations", domain)

    client = HaveIBeenSquatted(api_key)

    total_permutations = 0
    current_permutation = 0
    registered_count = 0
    unregistered_count = 0
    unregistered_domains = []

    try:
        async for message in client.nxdomain(domain):
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
                    registered_count += 1
                    perm_domain = message.permutation.domain.fqdn
                    perm_kind = message.permutation.kind.value
                    logging.info("registered: %s (%s)", perm_domain, perm_kind)

            elif message.op == Operation.LEVENSHTEIN and message.permutation:
                unregistered_count += 1
                perm_domain = message.permutation.domain.fqdn
                perm_kind = message.permutation.kind.value
                distance = message.data
                unregistered_domains.append((perm_domain, perm_kind, distance))
                logging.info("available: %s (%s, distance=%d)", perm_domain, perm_kind, distance)

    except Exception as e:
        logging.error("analysis failed: %s", e)
        return

    # concise summary
    logging.info(
        "summary: permutations=%d registered=%d unregistered=%d",
        total_permutations,
        registered_count,
        unregistered_count,
    )

    if total_permutations > 0:
        availability_rate = (unregistered_count / total_permutations) * 100
        logging.info("availability_rate=%.1f%%", availability_rate)

    if unregistered_domains:
        # Sort by edit distance (lower is more similar) and show top 10
        for domain_name, kind, distance in sorted(unregistered_domains, key=lambda x: x[2])[:10]:
            logging.info("candidate: %s (%s, distance=%d)", domain_name, kind, distance)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find unregistered (NXDOMAIN) permutations for a domain"
    )
    parser.add_argument("domain", help="domain name to analyze")
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


def main() -> None:
    args = parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if not args.api_key:
        logging.error("HIBS_API_KEY not set; set the environment variable or pass --api-key")
        raise SystemExit(1)

    domain = args.domain.strip()
    if not domain:
        logging.error("domain cannot be empty")
        raise SystemExit(1)

    asyncio.run(check_nxdomains(domain, args.api_key))


if __name__ == "__main__":
    main()
