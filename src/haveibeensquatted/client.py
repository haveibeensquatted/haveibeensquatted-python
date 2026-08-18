"""Main API client for Have I Been Squatted service.

This module provides the primary interface for interacting with the Have I Been
Squatted API. It handles authentication, HTTP requests, and streaming responses.
"""

import json
import urllib.parse
from collections.abc import AsyncIterator

from .http import DefaultHttpClient, HttpClient, HTTPError, RateLimitError, URLError
from .models import CTSearchResponse, CTSearchResult, HydrateItem, Message, UsageResponse
from .parser import StreamParser

# API constants
API_HOST = "https://api.haveibeensquatted.com"
API_VERSION = "v1"
CT_SEARCH_DOMAINS_MAX_FQDNS_PER_REQUEST = 100
CT_SEARCH_DOMAINS_MAX_URL_LENGTH = 7000
USAGE_MIN_MINUTES = 60
USAGE_MAX_MINUTES = 129_600


class HaveIBeenSquatted:
    """Main client for Have I Been Squatted API.

    This client provides methods to interact with all available endpoints
    of the Have I Been Squatted API. It handles API key authentication and
    streams responses in real-time.

    Example:
        ```python
        import asyncio
        from haveibeensquatted import HaveIBeenSquatted

        async def main():
            # Initialize client with API key
            client = HaveIBeenSquatted("ak_your_api_key_here")

            # Stream squatting results
            async for message in client.squat("example.com"):
                if message.op == Operation.META:
                    print(f"Progress: {message.data}")
                elif message.op == Operation.GEO_IP:
                    print(f"Found IP: {message.data.ip}")

        asyncio.run(main())
        ```
    """

    def __init__(
        self,
        api_key: str,
        http_client: HttpClient | None = None,
        host: str | None = None,
        version: str | None = None,
        base_url: str | None = None,
    ) -> None:
        """Initialize the Have I Been Squatted client.

        Args:
            api_key: API key for API authentication (must start with 'ak_')
            http_client: Optional custom HTTP client implementation.
                        If None, uses DefaultHttpClient with urllib
            host: Optional API host (defaults to production)
            version: Optional API version (defaults to v1)
            base_url: Optional complete base URL (overrides host/version)

        Raises:
            ValueError: If api_key is empty or doesn't start with 'ak_'

        Note:
            API keys can expire or be revoked. Expired/revoked keys will return
            HTTP 401 Unauthorized. API keys can also be scoped to specific endpoints;
            missing scopes will return HTTP 403 Forbidden.
        """
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")
        api_key = api_key.strip()
        if not api_key.startswith("ak_"):
            raise ValueError("API key must start with 'ak_'")
        self.api_key = api_key

        if base_url:
            self.base_url = base_url.rstrip("/")
        else:
            api_host = host or API_HOST
            api_version = version or API_VERSION
            self.base_url = urllib.parse.urljoin(api_host + "/", api_version)

        # Set up default headers with API key
        self.headers = {"Authorization": f"Bearer {self.api_key}"}

        self.http_client = http_client or DefaultHttpClient()
        self.parser = StreamParser()

    async def squat(self, domain: str) -> AsyncIterator[Message]:
        """Look up domain squatting permutations.

        This endpoint analyzes a domain for potential squatting attempts by
        generating various permutations and checking their registration status,
        hosting information, and other security-relevant data.

        Args:
            domain: The domain to analyze for squatting

        Yields:
            Message objects containing streaming results from the API

        Raises:
            ValueError: If domain is empty or invalid
            HTTPError: If the HTTP request fails
            URLError: If there's a network or URL error

        Example:
            ```python
            async for message in client.squat("example.com"):
                if message.op == Operation.META and message.data.kind == MetaKind.PROGRESS:
                    progress = message.data.data
                    if isinstance(progress, list) and len(progress) >= 2:
                        print(f"Progress: {progress[0]}/{progress[1]}")
                elif message.op == Operation.GEO_IP:
                    print(f"IP {message.data.ip} in {message.data.country.iso_code}")
            ```
        """
        if not domain or not domain.strip():
            raise ValueError("Domain cannot be empty")

        url = urllib.parse.urljoin(self.base_url + "/", f"lookup/squat/{domain.strip()}")

        try:
            async for message in self._stream_messages(url, self.headers):
                yield message
        except HTTPError as e:
            raise HTTPError(f"Failed to lookup squatting for {domain}: {e}") from e
        except URLError as e:
            raise URLError(f"Network error during squatting lookup for {domain}: {e}") from e

    async def nxdomain(self, domain: str) -> AsyncIterator[Message]:
        """Look up unregistered domain permutations.

        This endpoint generates various permutations of a domain and checks
        which ones are unregistered (NXDOMAIN). This is useful for finding
        available domains or potential typosquatting opportunities.

        Args:
            domain: The domain to analyze for unregistered permutations

        Yields:
            Message objects containing streaming results from the API

        Raises:
            ValueError: If domain is empty or invalid
            HTTPError: If the HTTP request fails
            URLError: If there's a network or URL error

        Example:
            ```python
            async for message in client.nxdomain("example.com"):
                if message.op == Operation.LEVENSHTEIN:
                    print("Available:", message.permutation.domain.fqdn)
                elif message.op == Operation.IP_ENUMERATION:
                    print("Registered:", message.permutation.domain.fqdn)
            ```
        """
        if not domain or not domain.strip():
            raise ValueError("Domain cannot be empty")

        url = urllib.parse.urljoin(self.base_url + "/", f"lookup/nxdomain/{domain.strip()}")

        try:
            async for message in self._stream_messages(url, self.headers):
                yield message
        except HTTPError as e:
            raise HTTPError(f"Failed to lookup NXDOMAIN for {domain}: {e}") from e
        except URLError as e:
            raise URLError(f"Network error during NXDOMAIN lookup for {domain}: {e}") from e

    async def analyze(self, domain: str) -> AsyncIterator[Message]:
        """Perform comprehensive domain analysis.

        This endpoint provides a comprehensive analysis of a single domain,
        including DNS records, hosting information,
        security classification, and other relevant data.

        Args:
            domain: The domain to analyze

        Yields:
            Message objects containing streaming results from the API

        Raises:
            ValueError: If domain is empty or invalid
            HTTPError: If the HTTP request fails
            URLError: If there's a network or URL error

        Example:
            ```python
            async for message in client.analyze("example.com"):
                if message.op == Operation.DNS:
                    print("DNS:", message.data)
            ```
        """
        if not domain or not domain.strip():
            raise ValueError("Domain cannot be empty")

        url = urllib.parse.urljoin(self.base_url + "/", f"analyze/{domain.strip()}")

        try:
            async for message in self._stream_messages(url, self.headers):
                yield message
        except HTTPError as e:
            raise HTTPError(f"Failed to analyze {domain}: {e}") from e
        except URLError as e:
            raise URLError(f"Network error during analysis of {domain}: {e}") from e

    async def _stream_messages(self, url: str, headers: dict[str, str]) -> AsyncIterator[Message]:
        """Internal method to stream messages from an API endpoint.

        Args:
            url: The URL to request
            headers: HTTP headers to include

        Yields:
            Parsed Message objects from the stream
        """
        async for message in self.parser.parse_stream(self.http_client.stream_get(url, headers)):
            yield message

    async def ct_search(
        self,
        pattern: str,
        kind: str = "regex",
        limit: int = 100,
        field: str | None = None,
        include_precert: bool = False,
    ) -> CTSearchResponse:
        """Search certificate transparency logs.

        Args:
            pattern: Regular expression matched against indexed CT names.
            kind: Search strategy. The current service supports ``regex``.
            limit: Requested maximum number of results.
            field: Optional low-level CT name-index selector. This is not a
                certificate field such as issuer or Common Name; omit it to let
                the service select the index automatically.
            include_precert: Compatibility parameter forwarded to the service.
                The current service does not use it to filter precertificate-only
                results.

        Returns:
            Parsed CT search results and the response truncation indicator.
        """
        if not pattern or not pattern.strip():
            raise ValueError("Pattern cannot be empty")
        params: dict[str, str] = {
            "pattern": pattern.strip(),
            "kind": kind,
            "limit": str(limit),
            "include_precert": "true" if include_precert else "false",
        }
        if field:
            params["field"] = field
        url = urllib.parse.urljoin(self.base_url + "/", "ct/search")
        url = f"{url}?{urllib.parse.urlencode(params)}"
        data, headers = await self._get_json(url)
        if not isinstance(data, list):
            raise TypeError("CT search response must be a list")
        results = [self.parser._parse_ct_search_result(item) for item in data]
        has_more_header = headers.get("x-has-more-value") or headers.get("X-Has-More-Value")
        has_more = False
        if isinstance(has_more_header, str):
            has_more = has_more_header.strip().lower() == "true"
        return CTSearchResponse(results=results, has_more=has_more)

    async def ct_search_domains(
        self, fqdns: list[str], include_precert: bool = False
    ) -> list[CTSearchResult]:
        """Look up exact FQDNs in certificate transparency logs."""
        if not fqdns:
            raise ValueError("fqdns cannot be empty")
        url = urllib.parse.urljoin(self.base_url + "/", "ct/search/domains")
        normalized_fqdns = self._normalize_fqdns(fqdns)
        chunks = self._chunk_ct_search_fqdns(url, normalized_fqdns, include_precert)

        results: list[CTSearchResult] = []
        for chunk in chunks:
            query_params: list[tuple[str, str]] = [("fqdn", fqdn) for fqdn in chunk]
            query_params.append(("include_precert", "true" if include_precert else "false"))
            chunk_url = f"{url}?{urllib.parse.urlencode(query_params)}"
            data, _headers = await self._get_json(chunk_url)
            if not isinstance(data, list):
                raise TypeError("CT search domains response must be a list")
            results.extend(self.parser._parse_ct_search_result(item) for item in data)

        return results

    async def ct_hydrate(self, occurrences: list[tuple[int, int]]) -> list[HydrateItem]:
        """Hydrate CT occurrences to get full certificate details."""
        if not occurrences:
            raise ValueError("occurrences cannot be empty")
        query_params = [("occ", f"{log_id}:{index}") for log_id, index in occurrences]
        url = urllib.parse.urljoin(self.base_url + "/", "ct/hydrate")
        url = f"{url}?{urllib.parse.urlencode(query_params)}"
        data, _headers = await self._get_json(url)
        if not isinstance(data, list):
            raise TypeError("CT hydrate response must be a list")
        return [self.parser._parse_hydrate_item(item) for item in data]

    async def usage(self, minutes: int = 1440) -> UsageResponse:
        """Get API usage data for a time window in minutes.

        Args:
            minutes: Usage period in minutes. Defaults to 1440 (24 hours).

        Returns:
            Parsed usage response containing period, totals, and hourly data.

        Raises:
            TypeError: If ``minutes`` is not an integer.
            ValueError: If ``minutes`` is outside the supported 60-minute to
                129,600-minute range.
        """
        if isinstance(minutes, bool) or not isinstance(minutes, int):
            raise TypeError("minutes must be an integer")
        if not USAGE_MIN_MINUTES <= minutes <= USAGE_MAX_MINUTES:
            raise ValueError(f"minutes must be between {USAGE_MIN_MINUTES} and {USAGE_MAX_MINUTES}")
        url = urllib.parse.urljoin(self.base_url + "/", "meta/usage")
        url = f"{url}?{urllib.parse.urlencode({'t': str(minutes)})}"
        data, _headers = await self._get_json(url)
        return self.parser._parse_usage_response(data)

    async def _get_json(self, url: str) -> tuple[object, dict[str, str]]:
        try:
            body, headers = await self.http_client.get(url, self.headers)
        except RateLimitError:
            raise
        try:
            decoded = body.decode("utf-8")
        except UnicodeDecodeError as e:
            raise HTTPError(f"Failed to decode response from {url}") from e
        try:
            data = json.loads(decoded)
        except json.JSONDecodeError as e:
            raise HTTPError(f"Failed to parse JSON response from {url}") from e
        headers_dict = dict(headers.items())
        return data, headers_dict

    @staticmethod
    def _normalize_fqdns(fqdns: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for fqdn in fqdns:
            candidate = fqdn.strip()
            if not candidate:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            normalized.append(candidate)
        if not normalized:
            raise ValueError("fqdns cannot be empty")
        return normalized

    @staticmethod
    def _ct_search_domains_url_length(
        base_url: str,
        fqdns: list[str],
        include_precert: bool,
    ) -> int:
        query_params: list[tuple[str, str]] = [("fqdn", fqdn) for fqdn in fqdns]
        query_params.append(("include_precert", "true" if include_precert else "false"))
        return len(f"{base_url}?{urllib.parse.urlencode(query_params)}")

    @staticmethod
    def _chunk_ct_search_fqdns(
        base_url: str, fqdns: list[str], include_precert: bool
    ) -> list[list[str]]:
        chunks: list[list[str]] = []
        current: list[str] = []

        for fqdn in fqdns:
            candidate = [*current, fqdn]
            too_many = len(candidate) > CT_SEARCH_DOMAINS_MAX_FQDNS_PER_REQUEST
            too_long = (
                HaveIBeenSquatted._ct_search_domains_url_length(
                    base_url,
                    candidate,
                    include_precert,
                )
                > CT_SEARCH_DOMAINS_MAX_URL_LENGTH
            )
            if current and (too_many or too_long):
                chunks.append(current)
                current = [fqdn]
                continue
            current = candidate

        if current:
            chunks.append(current)
        return chunks
