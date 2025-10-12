"""Tests for usage API client method."""

import json

import pytest

from haveibeensquatted import HaveIBeenSquatted


class MockHttpClient:
    def __init__(self, responses: list[tuple[bytes, dict[str, str]]]):
        self.responses = responses
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def get(self, url: str, headers: dict[str, str]) -> tuple[bytes, dict[str, str]]:
        self.calls.append((url, headers))
        return self.responses.pop(0)

    async def stream_get(self, url: str, headers: dict[str, str]):
        raise AssertionError("stream_get not expected in usage tests")


@pytest.mark.asyncio
async def test_usage_default_minutes():
    body = json.dumps(
        {
            "period": {"start": "2024-01-01T00:00:00Z", "end": "2024-01-02T00:00:00Z"},
            "totals": {"lookup_requests": 1, "ct_requests": 2, "total_requests": 3},
            "hourly": [
                {"timestamp": "2024-01-01T00:00:00Z", "lookup_requests": 1, "ct_requests": 2}
            ],
        }
    ).encode("utf-8")
    mock_client = MockHttpClient([(body, {})])
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    response = await client.usage()

    assert response.totals.total_requests == 3


@pytest.mark.asyncio
async def test_usage_custom_minutes():
    body = json.dumps(
        {
            "period": {"start": "2024-01-01T00:00:00Z", "end": "2024-01-01T01:00:00Z"},
            "totals": {"lookup_requests": 1, "ct_requests": 0, "total_requests": 1},
            "hourly": [],
        }
    ).encode("utf-8")
    mock_client = MockHttpClient([(body, {})])
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    response = await client.usage(minutes=60)

    assert response.period.end == "2024-01-01T01:00:00Z"
