#!/usr/bin/env python3
"""Example CLI tool for comprehensive domain analysis.

This script demonstrates how to use the Have I Been Squatted Python SDK
to perform comprehensive analysis of a single domain.

Usage:
    export HIBS_API_KEY="ak_your_api_key_here"
    python analyze.py example.com

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

# Classification thresholds
LEGITIMATE_THRESHOLD = 0.7
PHISHING_THRESHOLD = 0.5
PARKED_THRESHOLD = 0.5


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


async def analyze_domain(domain: str, api_key: str) -> None:
    """Perform comprehensive analysis of a domain.

    Args:
        domain: The domain to analyze
        api_key: API key for API authentication
    """
    logging.info("starting analysis of %s", domain)

    client = HaveIBeenSquatted(api_key)

    dns_records = None
    classification = None
    http_banner = None
    technologies = None
    geo_data = None
    screenshot_url = None
    redirect_chain = None

    try:
        async for message in client.analyze(domain):
            if message.op == Operation.META:
                if message.data and message.data.kind == MetaKind.DONE:
                    logging.info("analysis complete")
                    break
                elif message.data and message.data.kind == MetaKind.ERROR:
                    error_msg = message.data.data
                    logging.error("%s", error_msg)
                    break

            elif message.op == Operation.DNS:
                dns_records = message.data
                # compact DNS record outputs
                if dns_records.a:
                    logging.info("A: %s", ", ".join(dns_records.a))
                if dns_records.aaaa:
                    logging.info("AAAA: %s", ", ".join(dns_records.aaaa))
                if dns_records.mx:
                    logging.info("MX: %s", ", ".join(dns_records.mx))
                if dns_records.txt:
                    logging.info("TXT: %s", ", ".join(dns_records.txt))
                if dns_records.cname:
                    logging.info("CNAME: %s", ", ".join(dns_records.cname))
                if dns_records.ns:
                    logging.info("NS: %s", ", ".join(dns_records.ns))

            elif message.op == Operation.CLASSIFICATION:
                classification = message.data
                logging.info(
                    "classification: legitimate=%.2f phishing=%.2f parked=%.2f",
                    classification.legitimate,
                    classification.phishing,
                    classification.parked,
                )

            elif message.op == Operation.HTTP_BANNER:
                http_banner = message.data
                logging.info("http_banner: %s", http_banner)

            elif message.op == Operation.TECHNOLOGIES:
                technologies = message.data
                logging.info("technologies: %s", ", ".join(technologies))

            elif message.op == Operation.GEO_IP:
                geo_data = message.data
                logging.info(
                    "geo: ip=%s country=%s asn=%s org=%s",
                    geo_data.ip,
                    geo_data.country.iso_code if geo_data.country else None,
                    geo_data.asn.number if geo_data.asn else None,
                    geo_data.asn.organization if geo_data.asn else None,
                )

            elif message.op == Operation.SCREENSHOT:
                screenshot_url = message.data
                logging.info("screenshot: %s", screenshot_url)

            elif message.op == Operation.REDIRECT_CHAIN:
                redirect_chain = message.data
                if redirect_chain:
                    for i, redirect in enumerate(redirect_chain):
                        status = f" ({redirect.status})" if redirect.status else ""
                        logging.info("redirect %d: %s%s", i + 1, redirect.url, status)

    except Exception as e:
        log_common_error(e)
        return

    # concise summary
    if classification:
        if classification.legitimate > LEGITIMATE_THRESHOLD:
            logging.info("summary: classification=legitimate")
        elif classification.phishing > PHISHING_THRESHOLD:
            logging.warning("summary: classification=phishing")
        elif classification.parked > PARKED_THRESHOLD:
            logging.info("summary: classification=parked")
        else:
            logging.info("summary: classification=unclear")

    if geo_data:
        logging.info(
            "summary: hosted_country=%s provider=%s",
            geo_data.country.iso_code if geo_data.country else None,
            geo_data.asn.organization if geo_data.asn else None,
        )

    if technologies:
        logging.info("summary: technologies=%s", ", ".join(technologies[:5]))

    if http_banner:
        logging.info("summary: server=%s", http_banner)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Perform a comprehensive analysis of a domain")
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

    configure_logging(args.log_level)

    api_key = resolve_api_key(args.api_key)
    if not api_key:
        logging.error("HIBS_API_KEY not set; set the environment variable or pass --api-key")
        raise SystemExit(1)

    domain = args.domain.strip()
    if not domain:
        logging.error("domain cannot be empty")
        raise SystemExit(1)

    asyncio.run(analyze_domain(domain, api_key))


if __name__ == "__main__":
    main()
