"""Tests for CT API client methods."""

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
        raise AssertionError("stream_get not expected in CT tests")


@pytest.mark.asyncio
async def test_ct_search_parses_has_more_header():
    body = json.dumps(
        [
            {
                "name": "example.com",
                "labels": {"tld": "com", "etld1": "example.com", "domain": "example"},
                "is_precert": False,
                "log_id": 1,
                "index": 2,
                "occurrences_count": 1,
                "last_seen_ts": 10,
                "occurrences": [{"log_id": 1, "kind": 0, "ts_sec": 10, "index": 2}],
            }
        ]
    ).encode("utf-8")
    mock_client = MockHttpClient([(body, {"x-has-more-value": "true"})])
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    response = await client.ct_search("example")

    assert response.has_more is True
    assert response.results[0].name == "example.com"


@pytest.mark.asyncio
async def test_ct_search_domains():
    body = json.dumps(
        [
            {
                "name": "example.com",
                "labels": {"tld": "com", "etld1": "example.com", "domain": "example"},
                "is_precert": False,
            }
        ]
    ).encode("utf-8")
    mock_client = MockHttpClient([(body, {})])
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    results = await client.ct_search_domains(["example.com"])

    assert len(results) == 1
    assert results[0].name == "example.com"


@pytest.mark.asyncio
async def test_ct_hydrate():
    body = json.dumps([{"log_id": 1, "index": 2, "error": "missing"}]).encode("utf-8")
    mock_client = MockHttpClient([(body, {})])
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    results = await client.ct_hydrate([(1, 2)])

    assert results[0].log_id == 1
    assert results[0].error == "missing"
