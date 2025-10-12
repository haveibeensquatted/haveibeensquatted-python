"""Tests for CT API client methods."""

import json
import urllib.parse

import pytest

import haveibeensquatted.client as client_module
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


@pytest.mark.asyncio
async def test_ct_search_domains_chunks_requests_when_domain_count_exceeds_limit():
    body_one = json.dumps(
        [
            {
                "name": "one.example.com",
                "labels": {"tld": "com", "etld1": "example.com", "domain": "example"},
                "is_precert": False,
            }
        ]
    ).encode("utf-8")
    body_two = json.dumps(
        [
            {
                "name": "two.example.com",
                "labels": {"tld": "com", "etld1": "example.com", "domain": "example"},
                "is_precert": False,
            }
        ]
    ).encode("utf-8")
    mock_client = MockHttpClient([(body_one, {}), (body_two, {})])
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    fqdns = [f"d{i}.example.com" for i in range(101)]
    results = await client.ct_search_domains(fqdns)

    assert len(results) == 2
    assert len(mock_client.calls) == 2
    first_qs = urllib.parse.parse_qs(urllib.parse.urlparse(mock_client.calls[0][0]).query)
    second_qs = urllib.parse.parse_qs(urllib.parse.urlparse(mock_client.calls[1][0]).query)
    assert len(first_qs["fqdn"]) == 100
    assert len(second_qs["fqdn"]) == 1


@pytest.mark.asyncio
async def test_ct_search_domains_chunks_requests_when_url_too_long(monkeypatch):
    monkeypatch.setattr(client_module, "CT_SEARCH_DOMAINS_MAX_URL_LENGTH", 120)

    body_one = json.dumps(
        [
            {
                "name": "a.example.com",
                "labels": {"tld": "com", "etld1": "example.com", "domain": "example"},
                "is_precert": False,
            }
        ]
    ).encode("utf-8")
    body_two = json.dumps(
        [
            {
                "name": "b.example.com",
                "labels": {"tld": "com", "etld1": "example.com", "domain": "example"},
                "is_precert": False,
            }
        ]
    ).encode("utf-8")
    mock_client = MockHttpClient([(body_one, {}), (body_two, {})])
    client = HaveIBeenSquatted("ak_test_token", http_client=mock_client)

    fqdns = [
        "very-long-domain-name-number-one.example.com",
        "very-long-domain-name-number-two.example.com",
    ]
    results = await client.ct_search_domains(fqdns)

    assert len(results) == 2
    assert len(mock_client.calls) == 2
