#!/usr/bin/env python3
"""Regenerate tests/data.jsonl using the squat lookup stream."""

import argparse
import asyncio
import os
import urllib.parse
from pathlib import Path

from haveibeensquatted.http import DefaultHttpClient

API_BASE = "https://api.haveibeensquatted.com/v1/"
DEFAULT_DOMAIN = "microsoft.com"
DEFAULT_OUTPUT = Path("tests/data.jsonl")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Regenerate tests/data.jsonl from the API stream.")
    parser.add_argument(
        "--domain",
        default=DEFAULT_DOMAIN,
        help=f"domain to use (default: {DEFAULT_DOMAIN})",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"output path (default: {DEFAULT_OUTPUT})",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    api_key = os.getenv("HIBS_API_KEY")
    if not api_key:
        raise SystemExit("HIBS_API_KEY is required")

    url = urllib.parse.urljoin(API_BASE, f"lookup/squat/{args.domain}")
    headers = {"Authorization": f"Bearer {api_key}"}

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    client = DefaultHttpClient()
    with output_path.open("wb") as handle:
        async for chunk in client.stream_get(url, headers):
            handle.write(chunk)


if __name__ == "__main__":
    asyncio.run(main())
