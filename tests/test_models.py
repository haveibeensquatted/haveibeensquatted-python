"""Tests for data models."""

import json
from pathlib import Path

import jsonschema
import pytest

from haveibeensquatted import (
    CertificateDetails,
    Classification,
    ClassificationKind,
    CTSearchResponse,
    CTSearchResult,
    DnsRecords,
    Domain,
    GeoIpAsn,
    GeoIpCountry,
    GeoIpData,
    HourlyUsage,
    HydrateItem,
    LookupEvent,
    MetaData,
    MetaKind,
    NxdomainMetadata,
    OccurrenceRec,
    Operation,
    ParsedX509Certificate,
    PassiveDNSRecord,
    PassiveTLSRecord,
    Permutation,
    PermutationKind,
    PermutationResult,
    Redirect,
    RedirectKind,
    SearchResultLabels,
    SmtpMetadata,
    UsagePeriod,
    UsageResponse,
    UsageTotals,
)


class TestEnums:
    """Test enum classes."""

    def test_operation_enum(self):
        """Test Operation enum values."""
        assert Operation.LEVENSHTEIN.value == "Levenshtein"
        assert Operation.GEO_IP.value == "GeoIp"
        assert Operation.META.value == "Meta"
        assert Operation.NXDOMAIN.value == "Nxdomain"
        assert Operation.MX_CHECK.value == "MxCheck"
        assert Operation.ORIGIN_X509.value == "OriginX509"
        assert Operation.PASSIVE_DNS.value == "PassiveDns"
        assert Operation.PASSIVE_TLS.value == "PassiveTls"
        assert Operation.CERTIFICATE_TRANSPARENCY.value == "CertificateTransparency"

    def test_meta_kind_enum(self):
        """Test MetaKind enum values."""
        assert MetaKind.PROGRESS.value == "Progress"
        assert MetaKind.ERROR.value == "Error"
        assert MetaKind.DONE.value == "Done"
        assert MetaKind.TIMEOUT.value == "Timeout"
        assert MetaKind.STORED_RESULT.value == "StoredResult"

    def test_permutation_kind_enum(self):
        """Test PermutationKind enum values."""
        assert PermutationKind.ADDITION.value == "Addition"
        assert PermutationKind.BITSQUATTING.value == "Bitsquatting"
        assert PermutationKind.HOMOGLYPH.value == "Homoglyph"
        assert PermutationKind.CERTIFICATE_TRANSPARENCY.value == "CertificateTransparency"
        assert PermutationKind.FAUX_TLD.value == "FauxTld"
        assert PermutationKind.USER_CONTEXT.value == "UserContext"
        assert PermutationKind.UNKNOWN.value == "Unknown"

    def test_classification_kind_enum(self):
        """Test ClassificationKind enum values."""
        assert ClassificationKind.LEGITIMATE.value == "legitimate"
        assert ClassificationKind.PHISHING.value == "phishing"
        assert ClassificationKind.PARKED.value == "parked"


class TestDataClasses:
    """Test dataclass models."""

    def test_domain(self):
        """Test Domain dataclass."""
        domain = Domain(fqdn="example.com", tld="com", domain="example")
        assert domain.fqdn == "example.com"
        assert domain.tld == "com"
        assert domain.domain == "example"

    def test_geo_ip_asn(self):
        """Test GeoIpAsn dataclass."""
        asn = GeoIpAsn(number=12345, organization="Example Corp")
        assert asn.number == 12345
        assert asn.organization == "Example Corp"

    def test_geo_ip_country(self):
        """Test GeoIpCountry dataclass."""
        country = GeoIpCountry(continent="North America", iso_code="US")
        assert country.continent == "North America"
        assert country.iso_code == "US"

    def test_geo_ip_data(self):
        """Test GeoIpData dataclass."""
        asn = GeoIpAsn(number=12345, organization="Example Corp")
        country = GeoIpCountry(continent="North America", iso_code="US")
        geo_data = GeoIpData(ip="1.2.3.4", asn=asn, country=country)

        assert geo_data.asn == asn
        assert geo_data.country == country
        assert geo_data.ip == "1.2.3.4"

    def test_classification(self):
        """Test Classification dataclass."""
        classification = Classification(legitimate=0.8, phishing=0.1, parked=0.1)
        assert classification.legitimate == 0.8
        assert classification.phishing == 0.1
        assert classification.parked == 0.1

    def test_permutation(self):
        """Test Permutation dataclass."""
        domain = Domain(fqdn="example.com", tld="com", domain="example")
        permutation = Permutation(domain=domain, kind=PermutationKind.ADDITION)

        assert permutation.domain == domain
        assert permutation.kind == PermutationKind.ADDITION

    def test_redirect(self):
        """Test Redirect dataclass."""
        redirect = Redirect(url="https://example.com", status=301, kind=RedirectKind.HTTP)
        assert redirect.url == "https://example.com"
        assert redirect.status == 301
        assert redirect.kind == RedirectKind.HTTP

    def test_dns_records(self):
        """Test DnsRecords dataclass."""
        dns = DnsRecords(
            a=["1.2.3.4"],
            aaaa=["::1"],
            mx=["mail.example.com"],
            txt=["v=spf1 include:_spf.example.com ~all"],
            cname=["www.example.com"],
            ns=["ns1.example.com", "ns2.example.com"],
        )

        assert dns.a == ["1.2.3.4"]
        assert dns.aaaa == ["::1"]
        assert dns.mx == ["mail.example.com"]
        assert dns.txt == ["v=spf1 include:_spf.example.com ~all"]
        assert dns.cname == ["www.example.com"]
        assert dns.ns == ["ns1.example.com", "ns2.example.com"]

    def test_meta_data(self):
        """Test MetaData dataclass."""
        meta = MetaData(kind=MetaKind.PROGRESS, data=[1, 10])
        assert meta.kind == MetaKind.PROGRESS
        assert meta.data == [1, 10]

    def test_permutation_result(self):
        """Test PermutationResult dataclass."""
        domain = Domain(fqdn="example.com", tld="com", domain="example")
        permutation = Permutation(domain=domain, kind=PermutationKind.ADDITION)

        result = PermutationResult(
            permutation=permutation,
            distance=1,
            http_banner="nginx/1.18.0",
            dns_a=["1.2.3.4"],
        )

        assert result.permutation == permutation
        assert result.distance == 1
        assert result.http_banner == "nginx/1.18.0"
        assert result.dns_a == ["1.2.3.4"]

    def test_lookup_event(self):
        """Test LookupEvent dataclass."""
        domain = Domain(fqdn="example.com", tld="com", domain="example")
        permutation = Permutation(domain=domain, kind=PermutationKind.ADDITION)
        result = PermutationResult(permutation=permutation)

        event = LookupEvent(permutation=permutation, data=result)

        assert event.permutation == permutation
        assert event.data == result


class TestNewModels:
    """Test newly added models."""

    def test_certificate_details(self):
        details = CertificateDetails(
            subject_name="example.com",
            san_list=["example.com", "www.example.com"],
            issuer="Example CA",
            valid_from=1.0,
            valid_to=2.0,
            certificate_transparency_compliance="Compliant",
            certificate_id=123,
            signed_certificate_timestamp_list=[{"log_id": "1"}],
            protocol="TLS 1.3",
            key_exchange="ECDHE",
            cipher="AES_128_GCM",
        )
        assert details.subject_name == "example.com"
        assert details.certificate_id == 123

    def test_parsed_x509_certificate(self):
        cert = ParsedX509Certificate(
            fingerprint_sha256="abc",
            serial="123",
            subject_dn="CN=example.com",
            issuer_dn="CN=Example CA",
            not_before=1,
            not_after=2,
            ttl_days=30,
            key_alg="RSA",
            key_size_bits=2048,
            sig_alg_oid="1.2.3.4",
            san_dns=["example.com"],
            san_dns_count=1,
            san_ip=[],
            is_ca=False,
            path_len=None,
            policy_oids=[],
            ocsp_uris=[],
            crl_dp=[],
        )
        assert cert.fingerprint_sha256 == "abc"
        assert cert.is_ca is False

    def test_smtp_metadata(self):
        metadata = SmtpMetadata(is_positive=True, response="ok")
        assert metadata.is_positive is True
        assert metadata.response == "ok"

    def test_nxdomain_metadata(self):
        metadata = NxdomainMetadata(query={"qname": "example.com"}, soa=None, trusted=True)
        assert metadata.trusted is True

    def test_passive_dns_record(self):
        record = PassiveDNSRecord(
            rrtype="A",
            rrname="example.com",
            rdata="1.2.3.4",
            time_first=1,
            time_last=2,
            count=3,
        )
        assert record.rrtype == "A"

    def test_passive_tls_record(self):
        record = PassiveTLSRecord(certificates=["abc"], subjects=["example.com"])
        assert record.certificates == ["abc"]

    def test_ct_models(self):
        labels = SearchResultLabels(tld="com", etld1="example.com", domain="example")
        occ = OccurrenceRec(log_id=1, kind=0, ts_sec=1, index=2)
        result = CTSearchResult(
            name="example.com",
            labels=labels,
            is_precert=False,
            occurrences=[occ],
        )
        response = CTSearchResponse(results=[result], has_more=False)
        hydrate = HydrateItem(log_id=1, index=2, cert=None, error=None)
        assert response.results[0].name == "example.com"
        assert hydrate.log_id == 1

    def test_usage_models(self):
        period = UsagePeriod(start="2024-01-01T00:00:00Z", end="2024-01-02T00:00:00Z")
        totals = UsageTotals(lookup_requests=1, ct_requests=2, total_requests=3)
        hourly = [HourlyUsage(timestamp="2024-01-01T00:00:00Z", lookup_requests=1, ct_requests=2)]
        response = UsageResponse(period=period, totals=totals, hourly=hourly)
        assert response.totals.total_requests == 3


class TestLookupEventSchema:
    """Test LookupEvent against JSON schema."""

    @pytest.fixture
    def schema(self):
        """Load JSON schema for LookupEvent."""
        schema_path = Path(__file__).parent / "schema" / "lookup_event_schema.json"
        with schema_path.open() as f:
            return json.load(f)

    def test_lookup_event_schema_validation(self, schema):
        """Test that LookupEvent can be validated against JSON schema."""
        # Create a valid LookupEvent
        domain = Domain(fqdn="example.com", tld="com", domain="example")
        permutation = Permutation(domain=domain, kind=PermutationKind.ADDITION)

        # Add some test data
        asn = GeoIpAsn(number=12345, organization="Example Corp")
        country = GeoIpCountry(continent="North America", iso_code="US")
        geo_data = GeoIpData(ip="1.2.3.4", asn=asn, country=country)

        classification = Classification(legitimate=0.8, phishing=0.1, parked=0.1)

        result = PermutationResult(
            permutation=permutation,
            distance=1,
            ips={"1.2.3.4": geo_data},
            classification=classification,
            http_banner="nginx/1.18.0",
            technologies=["nginx", "php"],
            dns_a=["1.2.3.4"],
            dns_aaaa=["::1"],
            dns_mx=["mail.example.com"],
            dns_txt=["v=spf1 include:_spf.example.com ~all"],
            dns_cname=["www.example.com"],
            dns_ns=["ns1.example.com"],
            redirect_chain=[{"url": "https://example.com", "status": 301, "kind": "Http"}],
        )

        event = LookupEvent(permutation=permutation, data=result)

        # Convert to dict for schema validation
        event_dict = {
            "permutation": {
                "domain": {
                    "fqdn": event.permutation.domain.fqdn,
                    "tld": event.permutation.domain.tld,
                    "domain": event.permutation.domain.domain,
                },
                "kind": event.permutation.kind.value,
            },
            "data": {
                "permutation": {
                    "domain": {
                        "fqdn": event.data.permutation.domain.fqdn,
                        "tld": event.data.permutation.domain.tld,
                        "domain": event.data.permutation.domain.domain,
                    },
                    "kind": event.data.permutation.kind.value,
                },
                "distance": event.data.distance,
                "ips": {
                    "1.2.3.4": {
                        "asn": {
                            "number": geo_data.asn.number,
                            "organization": geo_data.asn.organization,
                        },
                        "country": {
                            "continent": geo_data.country.continent,
                            "iso_code": geo_data.country.iso_code,
                        },
                        "ip": geo_data.ip,
                    }
                },
                "classification": {
                    "legitimate": classification.legitimate,
                    "phishing": classification.phishing,
                    "parked": classification.parked,
                },
                "http_banner": event.data.http_banner,
                "technologies": event.data.technologies,
                "dns_a": event.data.dns_a,
                "dns_aaaa": event.data.dns_aaaa,
                "dns_mx": event.data.dns_mx,
                "dns_txt": event.data.dns_txt,
                "dns_cname": event.data.dns_cname,
                "dns_ns": event.data.dns_ns,
                "redirect_chain": event.data.redirect_chain,
            },
        }

        # Validate against schema
        jsonschema.validate(event_dict, schema)

    def test_minimal_lookup_event_schema_validation(self, schema):
        """Test minimal LookupEvent against JSON schema."""
        domain = Domain(fqdn="example.com", tld="com", domain="example")
        permutation = Permutation(domain=domain, kind=PermutationKind.ADDITION)
        result = PermutationResult(permutation=permutation)
        event = LookupEvent(permutation=permutation, data=result)

        # Convert to dict for schema validation
        event_dict = {
            "permutation": {
                "domain": {
                    "fqdn": event.permutation.domain.fqdn,
                    "tld": event.permutation.domain.tld,
                    "domain": event.permutation.domain.domain,
                },
                "kind": event.permutation.kind.value,
            },
            "data": {
                "permutation": {
                    "domain": {
                        "fqdn": event.data.permutation.domain.fqdn,
                        "tld": event.data.permutation.domain.tld,
                        "domain": event.data.permutation.domain.domain,
                    },
                    "kind": event.data.permutation.kind.value,
                }
            },
        }

        # Validate against schema
        jsonschema.validate(event_dict, schema)
