"""Have I Been Squatted Python SDK.

A Python SDK for the Have I Been Squatted API that provides real-time
streaming analysis of domain squatting, unregistered domains, and
comprehensive domain security analysis.

Example:
    ```python
    import asyncio
    from haveibeensquatted import HaveIBeenSquatted, Operation, MetaKind

    async def main():
        client = HaveIBeenSquatted("ak_your_api_key")

        async for message in client.squat("example.com"):
            if message.op == Operation.META and message.data.kind == MetaKind.PROGRESS:
                print(f"Progress: {message.data.data}")

    asyncio.run(main())
    ```
"""

from importlib.metadata import version as get_version

from .client import API_HOST, API_VERSION, HaveIBeenSquatted
from .http import DefaultHttpClient, HttpClient, HTTPError, RateLimitError, URLError
from .models import (
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
    HydratedOccurrenceResult,
    HydrateItem,
    LookupEvent,
    Message,
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
from .parser import StreamParser

__version__ = get_version(__package__ or "haveibeensquatted")
__author__ = "Have I Been Squatted"
__email__ = "hello@haveibeensquatted.com"

__all__ = [
    # API constants
    "API_HOST",
    "API_VERSION",
    "CTSearchResponse",
    "CTSearchResult",
    "CertificateDetails",
    "Classification",
    "ClassificationKind",
    "DefaultHttpClient",
    "DnsRecords",
    "Domain",
    "GeoIpAsn",
    "GeoIpCountry",
    "GeoIpData",
    "HTTPError",
    # Main client
    "HaveIBeenSquatted",
    "HourlyUsage",
    # HTTP components
    "HttpClient",
    "HydrateItem",
    "HydratedOccurrenceResult",
    "LookupEvent",
    "Message",
    "MetaData",
    "MetaKind",
    "NxdomainMetadata",
    "OccurrenceRec",
    # Models
    "Operation",
    "ParsedX509Certificate",
    "PassiveDNSRecord",
    "PassiveTLSRecord",
    "Permutation",
    "PermutationKind",
    "PermutationResult",
    "RateLimitError",
    "Redirect",
    "RedirectKind",
    "SearchResultLabels",
    "SmtpMetadata",
    # Parser
    "StreamParser",
    "URLError",
    "UsagePeriod",
    "UsageResponse",
    "UsageTotals",
]
