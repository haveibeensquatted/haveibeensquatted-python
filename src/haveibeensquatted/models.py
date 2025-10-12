"""Data models for Have I Been Squatted API responses.

This module contains all the dataclasses and enums used to represent
API responses and streaming data from the Have I Been Squatted service.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


class Operation(Enum):
    """Enumeration of all possible operations in API responses."""

    LEVENSHTEIN = "Levenshtein"
    GEO_IP = "GeoIp"
    IP_ENUMERATION = "IpEnumeration"
    HTTP_BANNER = "HttpBanner"
    RDAP = "Rdap"
    WHOIS = "WhoIs"
    CLASSIFICATION = "Classification"
    META = "Meta"
    SCREENSHOT = "Screenshot"
    DNS = "Dns"
    TECHNOLOGIES = "Technologies"
    REDIRECT_CHAIN = "RedirectChain"
    REGISTRATION_METADATA = "RegistrationMetadata"
    NXDOMAIN = "Nxdomain"
    MX_CHECK = "MxCheck"
    ORIGIN_X509 = "OriginX509"
    PASSIVE_DNS = "PassiveDns"
    PASSIVE_TLS = "PassiveTls"
    CERTIFICATE_TRANSPARENCY = "CertificateTransparency"


class MetaKind(Enum):
    """Enumeration of metadata message types."""

    PROGRESS = "Progress"
    ERROR = "Error"
    HEARTBEAT = "Heartbeat"
    DONE = "Done"
    TIMEOUT = "Timeout"
    STORED_RESULT = "StoredResult"


class PermutationKind(Enum):
    """Enumeration of domain permutation types."""

    ADDITION = "Addition"
    BITSQUATTING = "Bitsquatting"
    HYPHENATION = "Hyphenation"
    INSERTION = "Insertion"
    OMISSION = "Omission"
    REPETITION = "Repetition"
    REPLACEMENT = "Replacement"
    SUBDOMAIN = "Subdomain"
    TRANSPOSITION = "Transposition"
    VOWEL_SWAP = "VowelSwap"
    VOWEL_SHUFFLE = "VowelShuffle"
    KEYWORD = "Keyword"
    TLD = "Tld"
    HOMOGLYPH = "Homoglyph"
    MAPPED = "Mapped"
    DOUBLE_VOWEL_INSERTION = "DoubleVowelInsertion"
    CERTIFICATE_TRANSPARENCY = "CertificateTransparency"
    FAUX_TLD = "FauxTld"
    USER_CONTEXT = "UserContext"
    UNKNOWN = "Unknown"


class ClassificationKind(Enum):
    """Enumeration of domain classification types."""

    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    PARKED = "parked"


@dataclass
class GeoIpAsn:
    """ASN (Autonomous System Number) information."""

    number: int | None
    organization: str | None


@dataclass
class GeoIpCountry:
    """Country information for IP geolocation."""

    continent: str | None
    iso_code: str | None


@dataclass
class GeoIpData:
    """Complete geolocation data for an IP address."""

    ip: str
    asn: GeoIpAsn | None = None
    country: GeoIpCountry | None = None


@dataclass
class Classification:
    """Domain classification scores."""

    legitimate: float
    phishing: float
    parked: float


@dataclass
class Domain:
    """Domain information."""

    fqdn: str
    tld: str
    domain: str


@dataclass
class Permutation:
    """Domain permutation information."""

    domain: Domain
    kind: PermutationKind


@dataclass
class Redirect:
    """HTTP redirect information."""

    url: str
    kind: RedirectKind
    status: int | None = None
    certificate: CertificateDetails | None = None


class RedirectKind(Enum):
    """Enumeration of redirect kinds."""

    INITIAL_REQUEST = "InitialRequest"
    HTTP = "Http"
    JAVASCRIPT = "Javascript"
    CLIENT = "Client"


@dataclass
class CertificateDetails:
    """Certificate details for redirects."""

    subject_name: str
    san_list: list[str]
    issuer: str
    valid_from: float
    valid_to: float
    certificate_transparency_compliance: str
    certificate_id: int
    signed_certificate_timestamp_list: list[dict[str, object]]
    key_exchange_group: str | None = None
    mac: str | None = None
    protocol: str = ""
    key_exchange: str = ""
    cipher: str = ""


@dataclass
class ParsedX509Certificate:
    """Parsed X.509 certificate data."""

    fingerprint_sha256: str
    serial: str
    subject_dn: str
    issuer_dn: str
    not_before: int
    not_after: int
    ttl_days: int
    key_alg: str
    key_size_bits: int
    sig_alg_oid: str
    san_dns: list[str]
    san_dns_count: int
    san_ip: list[str]
    is_ca: bool
    path_len: int | None
    policy_oids: list[str]
    ocsp_uris: list[str]
    crl_dp: list[str]


@dataclass
class SmtpMetadata:
    """SMTP metadata from MX checks."""

    is_positive: bool
    response: str


@dataclass
class NxdomainMetadata:
    """NXDOMAIN metadata results."""

    query: dict[str, object]
    soa: dict[str, object] | None
    trusted: bool


@dataclass
class PassiveDNSRecord:
    """Passive DNS record."""

    rrtype: str
    rrname: str
    rdata: str
    time_first: int
    time_last: int
    count: int


@dataclass
class PassiveTLSRecord:
    """Passive TLS record."""

    certificates: list[str]
    subjects: list[str]


@dataclass
class PermutationResult:
    """Complete result data for a domain permutation."""

    permutation: Permutation
    distance: int | None = None
    # normalized: GeoIpData or {"ip": str} for missing data
    ips: dict[str, GeoIpData | dict[str, str]] | None = None
    whois: str | Mapping[str, object] | None = None
    classification: Classification | None = None
    http_banner: str | None = None
    technologies: list[str] | None = None
    dns_aaaa: list[str] | None = None
    dns_a: list[str] | None = None
    dns_mx: list[str] | None = None
    dns_txt: list[str] | None = None
    dns_cname: list[str] | None = None
    dns_ns: list[str] | None = None
    rdap: Mapping[str, object] | None = None
    screenshot_url: str | None = None
    registration_metadata: Mapping[str, object] | None = None
    redirect_chain: list[dict[str, object]] | None = None  # normalized for serialization
    smtp_metadata: SmtpMetadata | None = None
    nxdomain_metadata: NxdomainMetadata | None = None
    origin_x509: ParsedX509Certificate | None = None
    passive_dns: list[PassiveDNSRecord] | None = None
    passive_tls: dict[str, PassiveTLSRecord] | None = None
    certificate_transparency: CTSearchResult | None = None


@dataclass
class LookupEvent:
    """Complete lookup event containing permutation and result data."""

    permutation: Permutation
    data: PermutationResult


@dataclass
class MetaData:
    """Metadata information for progress tracking and status updates."""

    kind: MetaKind
    data: list[int] | str | bool | Mapping[str, object] | None = None


@dataclass
class Message:
    """Individual message from the streaming API."""

    op: Operation
    permutation: Permutation | None = None
    data: object | None = None


@dataclass
class DnsRecords:
    """DNS record information."""

    a: list[str]
    aaaa: list[str]
    mx: list[str]
    txt: list[str]
    cname: list[str]
    ns: list[str]


@dataclass
class SearchResultLabels:
    """Parsed labels for CT search results."""

    tld: str
    etld1: str
    domain: str
    registrable_domain: str | None = None
    subdomain: str | None = None


@dataclass
class OccurrenceRec:
    """CT occurrence record."""

    log_id: int
    kind: int
    ts_sec: int
    index: int


@dataclass
class HydratedOccurrenceResult:
    """CT hydrated occurrence data."""

    occ: OccurrenceRec
    cert: ParsedX509Certificate


@dataclass
class CTSearchResult:
    """Certificate transparency search result."""

    name: str
    labels: SearchResultLabels
    is_precert: bool
    log_id: int | None = None
    index: int | None = None
    occurrences_count: int | None = None
    last_seen_ts: int | None = None
    occurrences: list[OccurrenceRec | HydratedOccurrenceResult] | None = None
    cert: ParsedX509Certificate | None = None


@dataclass
class CTSearchResponse:
    """CT search response wrapper."""

    results: list[CTSearchResult]
    has_more: bool


@dataclass
class HydrateItem:
    """CT hydrate response item."""

    log_id: int
    index: int
    cert: ParsedX509Certificate | None = None
    error: str | None = None


@dataclass
class UsagePeriod:
    """Usage response period."""

    start: str
    end: str


@dataclass
class UsageTotals:
    """Usage response totals."""

    lookup_requests: int
    ct_requests: int
    total_requests: int


@dataclass
class HourlyUsage:
    """Usage response hourly breakdown."""

    timestamp: str
    lookup_requests: int
    ct_requests: int


@dataclass
class UsageResponse:
    """Usage response."""

    period: UsagePeriod
    totals: UsageTotals
    hourly: list[HourlyUsage]
