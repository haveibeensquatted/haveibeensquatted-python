"""Tests for streaming parser."""

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from haveibeensquatted import (
    Classification,
    DnsRecords,
    Domain,
    GeoIpData,
    Message,
    NxdomainMetadata,
    Operation,
    PassiveDNSRecord,
    PassiveTLSRecord,
    Permutation,
    PermutationKind,
    PermutationResult,
    Redirect,
    RedirectKind,
    StreamParser,
)


async def _byte_iter_from_file(path: Path) -> AsyncIterator[bytes]:
    """Create async byte iterator from file."""
    with path.open("rb") as f:
        for line in f:
            # Ensure newline-delimited chunks
            yield line if line.endswith(b"\n") else line + b"\n"


@pytest.mark.asyncio
async def test_parse_and_merge_covers_all_fields():
    """Test that parser covers all fields from real data."""
    # Locate test data
    data_path = Path(__file__).resolve().parent / "data.jsonl"
    assert data_path.exists(), f"missing test data at {data_path}"

    parser = StreamParser()
    domain_messages: dict[str, list[Message]] = {}
    ops_seen: set[Operation] = set()

    async for msg in parser.parse_stream(_byte_iter_from_file(data_path)):
        ops_seen.add(msg.op)
        # Group by permutation domain fqdn when present
        if msg.permutation and msg.permutation.domain.fqdn:
            fqdn = msg.permutation.domain.fqdn
            domain_messages.setdefault(fqdn, []).append(msg)

    # Merge all messages to permutation results
    merged: dict[str, PermutationResult] = parser.merge_grouped_messages(domain_messages)

    assert merged, "no merged results produced"

    # Expected fields derived from operations present in dataset
    expected_fields: set[str] = {"permutation"}
    if Operation.LEVENSHTEIN in ops_seen:
        expected_fields.add("distance")
    if Operation.IP_ENUMERATION in ops_seen or Operation.GEO_IP in ops_seen:
        expected_fields.add("ips")
    if Operation.WHOIS in ops_seen:
        expected_fields.add("whois")
    if Operation.CLASSIFICATION in ops_seen:
        expected_fields.add("classification")
    if Operation.HTTP_BANNER in ops_seen:
        expected_fields.add("http_banner")
    if Operation.TECHNOLOGIES in ops_seen:
        expected_fields.add("technologies")
    if Operation.DNS in ops_seen:
        expected_fields.update(
            {
                "dns_a",
                "dns_aaaa",
                "dns_mx",
                "dns_txt",
                "dns_cname",
                "dns_ns",
                "dns_svcb",
                "dns_https",
                "dns_caa",
                "dns_tlsa",
                "dns_srv",
                "dns_naptr",
                "dns_ptr",
                "dns_dnskey",
                "dns_ds",
            }
        )
    if Operation.RDAP in ops_seen:
        expected_fields.add("rdap")
    if Operation.SCREENSHOT in ops_seen:
        expected_fields.add("screenshot_url")
    if Operation.REGISTRATION_METADATA in ops_seen:
        expected_fields.add("registration_metadata")
    if Operation.REDIRECT_CHAIN in ops_seen:
        expected_fields.add("redirect_chain")
    if Operation.MX_CHECK in ops_seen:
        expected_fields.add("smtp_metadata")
    if Operation.NXDOMAIN in ops_seen:
        expected_fields.add("nxdomain_metadata")
    if Operation.ORIGIN_X509 in ops_seen:
        expected_fields.add("origin_x509")
    if Operation.PASSIVE_DNS in ops_seen:
        expected_fields.add("passive_dns")
    if Operation.PASSIVE_TLS in ops_seen:
        expected_fields.add("passive_tls")
    if Operation.CERTIFICATE_TRANSPARENCY in ops_seen:
        expected_fields.add("certificate_transparency")

    covered: set[str] = set()

    for res in merged.values():
        # Minimal always-present fields
        assert res.permutation is not None
        covered.update(["permutation"])  # Always covered

        if res.distance is not None:
            covered.add("distance")
        if res.ips:
            # Validate ips typing - normalized: either GeoIpData or {"ip": str}
            for ip, geo in res.ips.items():
                assert isinstance(ip, str)
                assert isinstance(geo, GeoIpData | dict)
                if isinstance(geo, dict):
                    assert "ip" in geo  # Minimal entries have ip field
            covered.add("ips")
        if res.whois is not None:
            covered.add("whois")
        if res.classification is not None:
            assert isinstance(res.classification, Classification)
            covered.add("classification")
        if res.http_banner:
            covered.add("http_banner")
        if res.technologies:
            assert all(isinstance(t, str) for t in res.technologies)
            covered.add("technologies")
        if res.dns_aaaa is not None:
            covered.add("dns_aaaa")
        if res.dns_a is not None:
            covered.add("dns_a")
        if res.dns_mx is not None:
            covered.add("dns_mx")
        if res.dns_txt is not None:
            covered.add("dns_txt")
        if res.dns_cname is not None:
            covered.add("dns_cname")
        if res.dns_ns is not None:
            covered.add("dns_ns")
        if res.dns_svcb is not None:
            covered.add("dns_svcb")
        if res.dns_https is not None:
            covered.add("dns_https")
        if res.dns_caa is not None:
            covered.add("dns_caa")
        if res.dns_tlsa is not None:
            covered.add("dns_tlsa")
        if res.dns_srv is not None:
            covered.add("dns_srv")
        if res.dns_naptr is not None:
            covered.add("dns_naptr")
        if res.dns_ptr is not None:
            covered.add("dns_ptr")
        if res.dns_dnskey is not None:
            covered.add("dns_dnskey")
        if res.dns_ds is not None:
            covered.add("dns_ds")
        if res.rdap is not None:
            covered.add("rdap")
        if res.screenshot_url:
            covered.add("screenshot_url")
        if res.registration_metadata is not None:
            covered.add("registration_metadata")
        if res.redirect_chain:
            # Redirect_chain is normalized to List[Dict] for serialization
            assert all(isinstance(r, dict) and "url" in r for r in res.redirect_chain)
            covered.add("redirect_chain")
        if res.smtp_metadata is not None:
            covered.add("smtp_metadata")
        if res.nxdomain_metadata is not None:
            covered.add("nxdomain_metadata")
        if res.origin_x509 is not None:
            covered.add("origin_x509")
        if res.passive_dns is not None:
            covered.add("passive_dns")
        if res.passive_tls is not None:
            covered.add("passive_tls")
        if res.certificate_transparency is not None:
            covered.add("certificate_transparency")

    missing = expected_fields - covered
    assert not missing, f"missing coverage for fields: {sorted(missing)}"


@pytest.mark.asyncio
async def test_parse_single_message():
    """Test parsing a single JSON message."""
    parser = StreamParser()

    # Test message
    test_data = b'{"op": "Meta", "data": {"kind": "Progress", "data": [1, 10]}}\n'

    async def byte_iter():
        yield test_data

    messages = []
    async for msg in parser.parse_stream(byte_iter()):
        messages.append(msg)

    assert len(messages) == 1
    assert messages[0].op == Operation.META
    assert messages[0].data is not None


@pytest.mark.asyncio
async def test_parse_multiple_messages():
    """Test parsing multiple JSON messages."""
    parser = StreamParser()

    # Test messages
    test_data = (
        b'{"op": "Meta", "data": {"kind": "Progress", "data": [1, 10]}}\n'
        b'{"op": "Levenshtein", "data": 2}\n'
        b'{"op": "GeoIp", "data": {"ip": "1.2.3.4", "asn": {"number": 12345, '
        b'"organization": "Test Corp"}, "country": {"continent": "North America", '
        b'"iso_code": "US"}}}\n'
    )

    async def byte_iter():
        yield test_data

    messages = []
    async for msg in parser.parse_stream(byte_iter()):
        messages.append(msg)

    assert len(messages) == 3
    assert messages[0].op == Operation.META
    assert messages[1].op == Operation.LEVENSHTEIN
    assert messages[2].op == Operation.GEO_IP
    assert isinstance(messages[2].data, GeoIpData)
    assert messages[2].data.ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_parse_current_generic_operations_without_dropping_data():
    """Preserve current API operations that do not yet have typed payload models."""
    parser = StreamParser()
    test_data = (
        b'{"op":"DomainMetadata","data":{"char_count":7}}\n'
        b'{"op":"DomainStatus","data":{"status":"active zone"}}\n'
        b'{"op":"PageRank","data":{"page_rank_integer":6}}\n'
        b'{"op":"Security","data":{"findings":[]}}\n'
    )

    async def byte_iter():
        yield test_data

    messages = [message async for message in parser.parse_stream(byte_iter())]

    assert [message.op for message in messages] == [
        Operation.DOMAIN_METADATA,
        Operation.DOMAIN_STATUS,
        Operation.PAGE_RANK,
        Operation.SECURITY,
    ]
    assert messages[0].data == {"char_count": 7}
    assert messages[1].data == {"status": "active zone"}
    assert messages[2].data == {"page_rank_integer": 6}
    assert messages[3].data == {"findings": []}


@pytest.mark.asyncio
async def test_parse_partial_messages():
    """Test parsing messages that arrive in chunks."""
    parser = StreamParser()

    # Split message across chunks
    chunks = [
        b'{"op": "Meta", "data": {"kind": "Progress"',
        b', "data": [1, 10]}}\n',
        b'{"op": "Levenshtein", "data": 2}\n',
    ]

    async def byte_iter():
        for chunk in chunks:
            yield chunk

    messages = []
    async for msg in parser.parse_stream(byte_iter()):
        messages.append(msg)

    assert len(messages) == 2
    assert messages[0].op == Operation.META
    assert messages[1].op == Operation.LEVENSHTEIN


@pytest.mark.asyncio
async def test_parse_malformed_json():
    """Test that malformed JSON is handled gracefully."""
    parser = StreamParser()

    # Mix of valid and invalid JSON
    test_data = (
        b'{"op": "Meta", "data": {"kind": "Progress", "data": [1, 10]}}\n'
        b'{"invalid": json}\n'  # Invalid JSON
        b'{"op": "Levenshtein", "data": 2}\n'
    )

    async def byte_iter():
        yield test_data

    messages = []
    async for msg in parser.parse_stream(byte_iter()):
        messages.append(msg)

    # Should only get the valid messages
    assert len(messages) == 2
    assert messages[0].op == Operation.META
    assert messages[1].op == Operation.LEVENSHTEIN


def test_merge_messages():
    """Test merging messages into PermutationResult."""
    parser = StreamParser()

    # Create test messages
    domain = Domain(fqdn="example.com", tld="com", domain="example")
    permutation = Permutation(domain=domain, kind=PermutationKind.ADDITION)

    messages = [
        Message(op=Operation.LEVENSHTEIN, permutation=permutation, data=2),
        Message(op=Operation.HTTP_BANNER, permutation=permutation, data="nginx/1.18.0"),
        Message(
            op=Operation.CLASSIFICATION, permutation=permutation, data=Classification(0.8, 0.1, 0.1)
        ),
    ]

    result = parser.merge_messages("example.com", messages)

    assert result is not None
    assert result.permutation == permutation
    assert result.distance == 2
    assert result.http_banner == "nginx/1.18.0"
    assert result.classification is not None
    assert result.classification.legitimate == 0.8


def test_merge_messages_preserves_unmodeled_operation_data():
    """Keep recognized raw operation payloads when producing a merged result."""
    parser = StreamParser()
    domain = Domain(fqdn="example.com", tld="com", domain="example")
    permutation = Permutation(domain=domain, kind=PermutationKind.ADDITION)
    messages = [
        Message(
            op=Operation.DOMAIN_STATUS,
            permutation=permutation,
            data={"status": "active zone"},
        ),
        Message(
            op=Operation.DOMAIN_STATUS,
            permutation=permutation,
            data={"status": "registered"},
        ),
        Message(op=Operation.SECURITY, permutation=permutation, data={"findings": []}),
    ]

    result = parser.merge_messages("example.com", messages)

    assert result is not None
    assert result.unmodeled_operations == {
        "DomainStatus": [{"status": "active zone"}, {"status": "registered"}],
        "Security": [{"findings": []}],
    }


def test_parse_dns_records():
    """Test parsing DNS records."""
    parser = StreamParser()

    dns_data = {
        "a": ["1.2.3.4"],
        "aaaa": ["::1"],
        "mx": ["mail.example.com"],
        "txt": ["v=spf1 include:_spf.example.com ~all"],
        "cname": ["www.example.com"],
        "ns": ["ns1.example.com", "ns2.example.com"],
        "svcb": ["1 svc.example.com alpn=h2"],
        "https": ["1 . alpn=h2"],
        "caa": ["0 issue letsencrypt.org"],
        "tlsa": ["3 1 1 abcdef"],
        "srv": ["10 5 443 service.example.com"],
        "naptr": ["100 10 U E2U+sip !^.*$!sip:info@example.com! ."],
        "ptr": ["host.example.com"],
        "dnskey": ["257 3 13 abcdef"],
        "ds": ["12345 13 2 abcdef"],
    }

    dns_records = parser._parse_dns(dns_data)

    assert isinstance(dns_records, DnsRecords)
    assert dns_records.a == ["1.2.3.4"]
    assert dns_records.aaaa == ["::1"]
    assert dns_records.mx == ["mail.example.com"]
    assert dns_records.txt == ["v=spf1 include:_spf.example.com ~all"]
    assert dns_records.cname == ["www.example.com"]
    assert dns_records.ns == ["ns1.example.com", "ns2.example.com"]
    assert dns_records.svcb == ["1 svc.example.com alpn=h2"]
    assert dns_records.https == ["1 . alpn=h2"]
    assert dns_records.caa == ["0 issue letsencrypt.org"]
    assert dns_records.tlsa == ["3 1 1 abcdef"]
    assert dns_records.srv == ["10 5 443 service.example.com"]
    assert dns_records.naptr == ["100 10 U E2U+sip !^.*$!sip:info@example.com! ."]
    assert dns_records.ptr == ["host.example.com"]
    assert dns_records.dnskey == ["257 3 13 abcdef"]
    assert dns_records.ds == ["12345 13 2 abcdef"]


def test_parse_redirect_chain():
    """Test parsing redirect chain."""
    parser = StreamParser()

    redirect_data = [
        {"url": "https://example.com", "status": 301, "kind": "Http"},
        {"url": "https://www.example.com", "status": 200, "kind": "Http"},
    ]

    redirects = parser._parse_redirect_chain(redirect_data)

    assert len(redirects) == 2
    assert isinstance(redirects[0], Redirect)
    assert redirects[0].url == "https://example.com"
    assert redirects[0].status == 301
    assert redirects[0].kind == RedirectKind.HTTP
    assert redirects[1].url == "https://www.example.com"
    assert redirects[1].status == 200


def test_parse_new_operation_types():
    """Test parsing new operation types."""
    parser = StreamParser()

    smtp = parser._parse_operation_data(Operation.MX_CHECK, {"is_positive": True, "response": "ok"})
    assert smtp.is_positive is True

    nxdomain = parser._parse_operation_data(
        Operation.NXDOMAIN, {"query": {"qname": "example.com"}, "soa": None, "trusted": True}
    )
    assert isinstance(nxdomain, NxdomainMetadata)

    passive_dns = parser._parse_operation_data(
        Operation.PASSIVE_DNS,
        [
            {
                "rrtype": "A",
                "rrname": "example.com",
                "rdata": "1.2.3.4",
                "time_first": 1,
                "time_last": 2,
                "count": 1,
            }
        ],
    )
    assert isinstance(passive_dns[0], PassiveDNSRecord)

    passive_tls = parser._parse_operation_data(
        Operation.PASSIVE_TLS,
        {"1.2.3.4": {"certificates": ["abc"], "subjects": ["example.com"]}},
    )
    assert isinstance(passive_tls["1.2.3.4"], PassiveTLSRecord)
