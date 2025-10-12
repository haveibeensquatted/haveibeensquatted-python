"""HTTP client interface and default implementation.

This module provides a protocol for HTTP clients and a default implementation
using Python's standard library. Users can provide their own HTTP client
implementations for custom behavior.
"""

import urllib.error
import urllib.request
from collections.abc import AsyncIterator, Mapping
from typing import Protocol, runtime_checkable

# HTTP status codes
HTTP_STATUS_TOO_MANY_REQUESTS = 429
HTTP_STATUS_BAD_REQUEST = 400


@runtime_checkable
class HttpClient(Protocol):
    """Protocol for HTTP clients that can stream responses.

    This protocol allows users to provide their own HTTP client implementations
    (e.g., httpx, aiohttp) while maintaining compatibility with the SDK.

    Example:
        ```python
        import httpx

        class HttpxClient:
            def __init__(self):
                self.client = httpx.AsyncClient()

            async def stream_get(self, url: str, headers: dict[str, str]) -> AsyncIterator[bytes]:
                async with self.client.stream("GET", url, headers=headers) as response:
                    async for chunk in response.aiter_bytes():
                        yield chunk

        # Use with SDK
        client = HaveIBeenSquatted(api_key, http_client=HttpxClient())
        ```
    """

    async def stream_get(self, url: str, headers: dict[str, str]) -> AsyncIterator[bytes]:
        """Stream HTTP GET response as bytes.

        Args:
            url: The URL to request
            headers: HTTP headers to include in the request

        Yields:
            Chunks of response data as bytes

        Raises:
            HTTPError: If the HTTP request fails
        """
        ...

    async def get(self, url: str, headers: dict[str, str]) -> tuple[bytes, Mapping[str, str]]:
        """Perform HTTP GET request and return response body and headers.

        Args:
            url: The URL to request
            headers: HTTP headers to include in the request

        Returns:
            Tuple of response body and headers

        Raises:
            HTTPError: If the HTTP request fails
            RateLimitError: If rate limited (HTTP 429)
        """
        ...


class DefaultHttpClient:
    """Default HTTP client implementation using Python's standard library.

    This implementation uses urllib.request and provides async streaming
    capabilities. It's suitable for most use cases and has minimal dependencies.
    """

    async def stream_get(self, url: str, headers: dict[str, str]) -> AsyncIterator[bytes]:
        """Stream HTTP GET response using urllib.request.

        Args:
            url: The URL to request
            headers: HTTP headers to include in the request

        Yields:
            Chunks of response data as bytes

        Raises:
            HTTPError: If the HTTP request fails
            URLError: If there's a network or URL error
        """
        # Create request with headers
        req = urllib.request.Request(url, headers=headers)

        try:
            # Open connection
            with urllib.request.urlopen(req) as response:
                # Check if response is successful
                if response.status == HTTP_STATUS_TOO_MANY_REQUESTS:
                    retry_after = _parse_retry_after(response.headers)
                    limit = _parse_rate_limit(response.headers)
                    raise RateLimitError(
                        "Rate limit exceeded", retry_after=retry_after, limit=limit
                    )
                if response.status >= HTTP_STATUS_BAD_REQUEST:
                    raise urllib.error.HTTPError(
                        url, response.status, response.reason, response.headers, None
                    )

                # Stream response in chunks
                while True:
                    chunk = response.read(8192)  # 8KB chunks
                    if not chunk:
                        break
                    yield chunk

        except urllib.error.HTTPError as e:
            if e.code == HTTP_STATUS_TOO_MANY_REQUESTS:
                retry_after = _parse_retry_after(e.headers)
                limit = _parse_rate_limit(e.headers)
                raise RateLimitError(
                    "Rate limit exceeded", retry_after=retry_after, limit=limit
                ) from e
            # Re-raise HTTP errors with more context
            raise HTTPError(f"HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            # Re-raise URL errors with more context
            raise URLError(f"URL error: {e.reason}") from e

    async def get(self, url: str, headers: dict[str, str]) -> tuple[bytes, Mapping[str, str]]:
        """Perform HTTP GET request using urllib.request."""
        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req) as response:
                if response.status == HTTP_STATUS_TOO_MANY_REQUESTS:
                    retry_after = _parse_retry_after(response.headers)
                    limit = _parse_rate_limit(response.headers)
                    raise RateLimitError(
                        "Rate limit exceeded", retry_after=retry_after, limit=limit
                    )
                if response.status >= HTTP_STATUS_BAD_REQUEST:
                    raise urllib.error.HTTPError(
                        url, response.status, response.reason, response.headers, None
                    )
                return response.read(), response.headers

        except urllib.error.HTTPError as e:
            if e.code == HTTP_STATUS_TOO_MANY_REQUESTS:
                retry_after = _parse_retry_after(e.headers)
                limit = _parse_rate_limit(e.headers)
                raise RateLimitError(
                    "Rate limit exceeded", retry_after=retry_after, limit=limit
                ) from e
            raise HTTPError(f"HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise URLError(f"URL error: {e.reason}") from e


class HTTPError(Exception):
    """Exception raised for HTTP-related errors."""

    pass


class URLError(Exception):
    """Exception raised for URL-related errors."""

    pass


class RateLimitError(Exception):
    """Exception raised when rate limit is exceeded."""

    def __init__(
        self, message: str, retry_after: float | None = None, limit: int | None = None
    ) -> None:
        super().__init__(message)
        self.retry_after = retry_after
        self.limit = limit


def _parse_retry_after(headers: object) -> float | None:
    if headers is None:
        return None
    retry_after = headers.get("Retry-After")
    if not retry_after:
        return None
    try:
        return float(retry_after)
    except (TypeError, ValueError):
        return None


def _parse_rate_limit(headers: object) -> int | None:
    if headers is None:
        return None
    limit = headers.get("X-RateLimit-Limit")
    if not limit:
        return None
    try:
        return int(limit)
    except (TypeError, ValueError):
        return None
