"""Tests for rate limiting behavior."""

import urllib.request

import pytest

from haveibeensquatted.http import DefaultHttpClient, RateLimitError


class _FakeResponse:
    def __init__(self, status: int, headers: dict[str, str]):
        self.status = status
        self.headers = headers
        self.reason = "Too Many Requests"

    def read(self, _size: int | None = None) -> bytes:
        return b""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_get_rate_limit_error(monkeypatch):
    def _fake_urlopen(_req):
        return _FakeResponse(429, {"Retry-After": "60", "X-RateLimit-Limit": "100"})

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    client = DefaultHttpClient()

    with pytest.raises(RateLimitError) as exc:
        await client.get("https://example.com", {})

    assert exc.value.retry_after == 60.0
    assert exc.value.limit == 100


@pytest.mark.asyncio
async def test_stream_get_rate_limit_error(monkeypatch):
    def _fake_urlopen(_req):
        return _FakeResponse(429, {"Retry-After": "150"})

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    client = DefaultHttpClient()

    with pytest.raises(RateLimitError) as exc:
        async for _ in client.stream_get("https://example.com", {}):
            pass

    assert exc.value.retry_after == 150.0
