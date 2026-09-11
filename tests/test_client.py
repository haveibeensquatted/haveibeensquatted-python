"""Tests for API client."""

from collections.abc import AsyncIterator

import pytest

from haveibeensquatted import (
    API_HOST,
    API_VERSION,
    HaveIBeenSquatted,
    HTTPError,
    Operation,
    URLError,
    __version__,
)


class MockHttpClient:
    """Mock HTTP client for testing."""

    def __init__(
        self,
        responses: list[bytes] | None = None,
        get_responses: list[tuple[bytes, dict[str, str]]] | None = None,
        should_raise: Exception | None = None,
    ):
        self.responses = responses or []
        self.get_responses = get_responses or []
        self.should_raise = should_raise
        self.calls = []
        self.get_calls = []

    async def stream_get(self, url: str, headers: dict[str, str]) -> AsyncIterator[bytes]:
        """Mock stream_get method."""
        self.calls.append((url, headers))

        if self.should_raise:
            raise self.should_raise

        for response in self.responses:
            yield response

    async def get(self, url: str, headers: dict[str, str]) -> tuple[bytes, dict[str, str]]:
        self.get_calls.append((url, headers))
        if self.should_raise:
            raise self.should_raise
        if not self.get_responses:
            return b"{}", {}
        return self.get_responses.pop(0)


@pytest.mark.asyncio
async def test_client_initialization():
    """Test client initialization."""
    client = HaveIBeenSquatted("ak_test_token")

    assert client.api_key == "ak_test_token"
    assert client.base_url == "https://api.haveibeensquatted.com/v1"
    assert client.headers == {
        "Authorization": "Bearer ak_test_token",
        "User-Agent": f"haveibeensquatted-python/{__version__}",
    }
    assert isinstance(client.http_client, type(client.http_client))  # DefaultHttpClient


@pytest.mark.asyncio
async def test_client_initialization_with_custom_http_client():
    """Test client initialization with custom HTTP client."""
    mock_client = MockHttpClient()
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    assert client.api_key == "ak_test_token"
    assert client.http_client is mock_client


@pytest.mark.asyncio
async def test_client_initialization_with_custom_base_url():
    """Test client initialization with custom base URL."""
    client = HaveIBeenSquatted("ak_test_token", base_url="https://test-api.example.com/v1")

    assert client.base_url == "https://test-api.example.com/v1"


@pytest.mark.asyncio
async def test_client_initialization_with_custom_host():
    """Test client initialization with custom host."""
    client = HaveIBeenSquatted("ak_test_token", host="https://staging-api.example.com")

    assert client.base_url == "https://staging-api.example.com/v1"


@pytest.mark.asyncio
async def test_client_initialization_with_custom_version():
    """Test client initialization with custom version."""
    client = HaveIBeenSquatted("ak_test_token", version="v2")

    assert client.base_url == "https://api.haveibeensquatted.com/v2"


@pytest.mark.asyncio
async def test_client_initialization_with_custom_host_and_version():
    """Test client initialization with custom host and version."""
    client = HaveIBeenSquatted("ak_test_token", host="https://dev-api.example.com", version="v3")

    assert client.base_url == "https://dev-api.example.com/v3"


def test_client_initialization_empty_token():
    """Test client initialization with empty token raises ValueError."""
    with pytest.raises(ValueError, match="API key cannot be empty"):
        HaveIBeenSquatted("")

    with pytest.raises(ValueError, match="API key cannot be empty"):
        HaveIBeenSquatted("   ")

    with pytest.raises(ValueError, match="API key must start with 'ak_'"):
        HaveIBeenSquatted("bad_token")


def test_api_constants():
    """Test that API constants are accessible and correct."""
    assert API_HOST == "https://api.haveibeensquatted.com"
    assert API_VERSION == "v1"


@pytest.mark.asyncio
async def test_squat_success():
    """Test successful squat lookup."""
    mock_client = MockHttpClient(
        [
            b'{"op": "Meta", "data": {"kind": "Progress", "data": [1, 10]}}\n',
            b'{"op": "Levenshtein", "data": 2}\n',
        ]
    )
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    messages = []
    async for message in client.squat("example.com"):
        messages.append(message)

    assert len(messages) == 2
    assert messages[0].op == Operation.META
    assert messages[1].op == Operation.LEVENSHTEIN

    # Check HTTP client was called correctly
    assert len(mock_client.calls) == 1
    url, headers = mock_client.calls[0]
    assert url == "https://api.haveibeensquatted.com/v1/lookup/squat/example.com"
    assert headers["Authorization"] == "Bearer ak_test_token"
    assert headers["User-Agent"] == f"haveibeensquatted-python/{__version__}"


@pytest.mark.asyncio
async def test_nxdomain_success():
    """Test successful nxdomain lookup."""
    mock_client = MockHttpClient(
        [
            b'{"op": "Meta", "data": {"kind": "Progress", "data": [1, 5]}}\n',
            b'{"op": "IpEnumeration", "data": ["1.2.3.4"]}\n',
        ]
    )
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    messages = []
    async for message in client.nxdomain("example.com"):
        messages.append(message)

    assert len(messages) == 2
    assert messages[0].op == Operation.META
    assert messages[1].op == Operation.IP_ENUMERATION

    # Check HTTP client was called correctly
    assert len(mock_client.calls) == 1
    url, headers = mock_client.calls[0]
    assert url == "https://api.haveibeensquatted.com/v1/lookup/nxdomain/example.com"
    assert headers["Authorization"] == "Bearer ak_test_token"


@pytest.mark.asyncio
async def test_analyze_success():
    """Test successful analyze lookup."""
    mock_client = MockHttpClient(
        [
            b'{"op": "Dns", "data": {"aaaa": ["::1"], "mx": ["mail.example.com"], '
            b'"txt": [], "cname": [], "ns": []}}\n',
            b'{"op": "Classification", "data": {"legitimate": 0.8, "phishing": 0.1, '
            b'"parked": 0.1}}\n',
        ]
    )
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    messages = []
    async for message in client.analyze("example.com"):
        messages.append(message)

    assert len(messages) == 2
    assert messages[0].op == Operation.DNS
    assert messages[1].op == Operation.CLASSIFICATION

    # Check HTTP client was called correctly
    assert len(mock_client.calls) == 1
    url, headers = mock_client.calls[0]
    assert url == "https://api.haveibeensquatted.com/v1/analyze/example.com"
    assert headers["Authorization"] == "Bearer ak_test_token"


@pytest.mark.asyncio
async def test_squat_empty_domain():
    """Test squat lookup with empty domain raises ValueError."""
    client = HaveIBeenSquatted("ak_test_token")

    with pytest.raises(ValueError, match="Domain cannot be empty"):
        async for _ in client.squat(""):
            pass

    with pytest.raises(ValueError, match="Domain cannot be empty"):
        async for _ in client.squat("   "):
            pass


@pytest.mark.asyncio
async def test_nxdomain_empty_domain():
    """Test nxdomain lookup with empty domain raises ValueError."""
    client = HaveIBeenSquatted("ak_test_token")

    with pytest.raises(ValueError, match="Domain cannot be empty"):
        async for _ in client.nxdomain(""):
            pass


@pytest.mark.asyncio
async def test_analyze_empty_domain():
    """Test analyze lookup with empty domain raises ValueError."""
    client = HaveIBeenSquatted("ak_test_token")

    with pytest.raises(ValueError, match="Domain cannot be empty"):
        async for _ in client.analyze(""):
            pass


@pytest.mark.asyncio
async def test_squat_http_error():
    """Test squat lookup with HTTP error."""
    mock_client = MockHttpClient(should_raise=HTTPError("HTTP 404: Not Found"))
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    with pytest.raises(HTTPError, match=r"Failed to lookup squatting for example\.com"):
        async for _ in client.squat("example.com"):
            pass


@pytest.mark.asyncio
async def test_squat_url_error():
    """Test squat lookup with URL error."""
    mock_client = MockHttpClient(should_raise=URLError("Connection failed"))
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    with pytest.raises(URLError, match=r"Network error during squatting lookup for example\.com"):
        async for _ in client.squat("example.com"):
            pass


@pytest.mark.asyncio
async def test_nxdomain_http_error():
    """Test nxdomain lookup with HTTP error."""
    mock_client = MockHttpClient(should_raise=HTTPError("HTTP 500: Internal Server Error"))
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    with pytest.raises(HTTPError, match=r"Failed to lookup NXDOMAIN for example\.com"):
        async for _ in client.nxdomain("example.com"):
            pass


@pytest.mark.asyncio
async def test_analyze_http_error():
    """Test analyze lookup with HTTP error."""
    mock_client = MockHttpClient(should_raise=HTTPError("HTTP 403: Forbidden"))
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    with pytest.raises(HTTPError, match=r"Failed to analyze example\.com"):
        async for _ in client.analyze("example.com"):
            pass


@pytest.mark.asyncio
async def test_domain_whitespace_handling():
    """Test that domain whitespace is handled correctly."""
    mock_client = MockHttpClient([b'{"op": "Meta", "data": {"kind": "Done"}}\n'])
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    # Test with leading/trailing whitespace
    async for _ in client.squat("  example.com  "):
        pass

    # Check that whitespace was stripped
    assert len(mock_client.calls) == 1
    url, _ = mock_client.calls[0]
    assert url == "https://api.haveibeensquatted.com/v1/lookup/squat/example.com"
