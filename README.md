# Have I Been Squatted Python SDK

A Python SDK for the [Have I Been Squatted](https://haveibeensquatted.com) API that provides real-time streaming analysis of domain squatting, unregistered domains and CT Log (Certificate Transparency Log) regex search.

## Features

- **Domain typosquatting lookup** - Detect potential typosquatting and brand squatting attempts
- **Unregistered domain discovery** - Find available domain permutations (NXDOMAIN)
- **Domain analysis** - Security and technical analysis for a single domain
- **Certificate transparency search** - Search, lookup domains, and hydrate CT occurrences
- **Usage metrics** - Fetch hourly and total API usage
- **Real-time streaming** - Process results as they arrive from the API
- **Flexible HTTP client** - Use your preferred HTTP library (httpx, aiohttp, etc.)
- **Type safe** - Full type hints and comprehensive error handling

## Installation

```bash
uv add haveibeensquatted
```

Or with pip:

```bash
pip install haveibeensquatted
```

## Quick start

```python
import asyncio
from haveibeensquatted import HaveIBeenSquatted, Operation, MetaKind

async def main():
    # Initialize client with your API key
    client = HaveIBeenSquatted("ak_your_api_key")

    # Analyze a domain for squatting attempts
    async for message in client.squat("example.com"):
        if message.op == Operation.META and message.data.kind == MetaKind.PROGRESS:
            progress = message.data.data
            if isinstance(progress, list) and len(progress) >= 2:
                print(f"Progress: {progress[0]}/{progress[1]}")
        elif message.op == Operation.GEO_IP:
            country = message.data.country.iso_code if message.data.country else None
            print(f"Found IP: {message.data.ip} in {country}")

asyncio.run(main())
```

## Authentication

Create an API key from https://haveibeensquatted.com/app/settings

```python
client = HaveIBeenSquatted("ak_your_api_key")
```

### Plans and feature access

Some features and endpoints may be gated based on your API key's plan tier. Different plans may have

- Different rate limits
- Verying access to features
- Varying data depth or result limits

[Get in touch](#support) for more information.

## API endpoints

### 1. Domain squatting analysis (`squat`)

Analyzes a domain for potential typosquatting and brand squatting attempts by generating various domain permutations (typos, homoglyphs, TLD variations, etc.) and checking their registration status, hosting information, and security classification.

The endpoint streams results in real-time, including:

- **IP enumeration** - Registered domains with their IP addresses and geolocation
- **Classification** - Machine learning scores indicating if domains are legitimate, phishing, or parked
- **DNS records** - A, MX, and other DNS records for registered domains
- **GeoIP data** - Geographic location and ASN information for IP addresses
- **HTTP banners** - Web server headers and technologies detected
- **Redirect chains** - HTTP redirects and certificate information
- **Certificate transparency** - CT log entries for domains
- **Passive DNS/TLS** - Historical DNS and TLS records

Use this endpoint to detect potential brand impersonation, typosquatting attacks, or unauthorized use of similar domain names.

```python
async for message in client.squat("example.com"):
    if message.op == Operation.IP_ENUMERATION:
        domain = message.permutation.domain.fqdn
        kind = message.permutation.kind.value
        print(f"Registered: {domain} ({kind})")
    elif message.op == Operation.CLASSIFICATION:
        classification = message.data
        print(f"Legitimate: {classification.legitimate:.2f}")
```

### 2. Unregistered domain discovery (`nxdomain`)

Generates various permutations of a domain and identifies which ones are unregistered (NXDOMAIN). This is useful for finding available domains, discovering potential typosquatting opportunities, or identifying domains that should be registered for brand protection.

The endpoint streams results including

- **Levenshtein distance** - Edit distance for typos and similar domains
- **Registered domains** - Permutations that are already registered (via IP enumeration)
- **Permutation types** - The type of transformation applied (addition, omission, replacement, etc.)

Use this endpoint to find available domain names, identify gaps in your domain portfolio, or discover potential defensive registrations needed to protect your brand.

```python
async for message in client.nxdomain("example.com"):
    if message.op == Operation.LEVENSHTEIN:
        domain = message.permutation.domain.fqdn
        distance = message.data
        print(f"Available: {domain} (edit distance: {distance})")
```

### 3. Comprehensive domain analysis (`analyze`)

Performs a comprehensive security and technical analysis of a single domain. This endpoint combines multiple data sources to provide a complete picture of a domain's infrastructure, security posture, and characteristics.

The endpoint streams results including:

- **DNS records** - Complete DNS information (A, AAAA, MX, TXT, NS, CNAME records)
- **GeoIP data** - Geographic location and ASN information for all IP addresses
- **HTTP banners** - Web server headers, status codes, and detected technologies
- **Redirect chains** - Complete HTTP redirect chains with certificate details
- **Classification** - Security classification scores (legitimate, phishing, parked)
- **Technologies** - Web technologies and frameworks detected
- **SMTP metadata** - Mail server information and configuration
- **X.509 certificates** - SSL/TLS certificate details from the origin server
- **Passive DNS/TLS** - Historical DNS and TLS records
- **Certificate transparency** - CT log entries for the domain
- **Screenshots** - Visual representation of the website (if available)

Use this endpoint for security assessments, infrastructure audits, or comprehensive domain intelligence gathering.

```python
async for message in client.analyze("example.com"):
    if message.op == Operation.DNS:
        dns = message.data
        print(f"A records: {dns.a}")
        print(f"MX records: {dns.mx}")
```

### 4. Certificate transparency (`ct_search`, `ct_search_domains`, `ct_hydrate`)

Search and query Certificate Transparency (CT) logs to discover SSL/TLS certificates issued for domains. CT logs provide a public record of all certificates issued by Certificate Authorities, making it possible to discover subdomains, detect unauthorized certificate issuance, and track certificate history.

**`ct_search`** - Search CT logs using regex patterns or other search types. Returns matching certificates with occurrence counts, timestamps, and basic metadata. Supports filtering by field, including/excluding precertificates, and pagination.

**`ct_search_domains`** - Look up exact FQDNs in CT logs. Useful for quickly checking if certificates exist for specific domains without regex matching.

**`ct_hydrate`** - Retrieve full certificate details for specific CT log occurrences. Takes log ID and index pairs and returns complete X.509 certificate information including subject, issuer, validity period, and extensions.

Use these endpoints for subdomain discovery, security monitoring, detecting unauthorized certificate issuance, or tracking certificate history for domains.

```python
# Search CT logs with regex
response = await client.ct_search("example", limit=5)
print(response.has_more, [r.name for r in response.results])

# Look up specific domains
results = await client.ct_search_domains(["example.com", "www.example.com"])

# Get full certificate details
occurrences = [(log_id, index) for log_id, index in [(1, 123), (2, 456)]]
certificates = await client.ct_hydrate(occurrences)
```

### 5. Usage metrics (`usage`)

Retrieve API usage statistics for your account, including request counts broken down by endpoint type and hourly usage patterns. Useful for monitoring API consumption, understanding usage patterns, and managing rate limits.

The response includes:

- **Period** - Start and end timestamps for the usage period
- **Totals** - Aggregate counts for lookup requests, CT requests, and total requests
- **Hourly breakdown** - Per-hour usage statistics for detailed analysis

By default, returns usage for the last 24 hours (1440 minutes). Specify a custom time period in minutes to get usage for a different timeframe.

Use this endpoint to monitor API usage, track consumption trends, or implement usage-based alerting.

```python
# Get last 24 hours of usage (default)
usage = await client.usage()
print(f"Total requests: {usage.totals.total_requests}")
print(f"Lookup requests: {usage.totals.lookup_requests}")
print(f"CT requests: {usage.totals.ct_requests}")

# Get last 7 days of usage
usage_week = await client.usage(minutes=10080)
```

## Rate limiting

Requests may be rate limited and return HTTP 429. The SDK raises `RateLimitError` and does not retry automatically

```python
from haveibeensquatted import RateLimitError

try:
    await client.usage()
except RateLimitError as exc:
    print(exc.retry_after, exc.limit)
```

## API constants

```python
from haveibeensquatted import API_HOST, API_VERSION

print(API_HOST)    # https://api.haveibeensquatted.com
print(API_VERSION) # v1
```

## Custom HTTP client

The SDK uses a protocol-based HTTP client that allows you to use your preferred HTTP library

```python
import httpx
from haveibeensquatted import HaveIBeenSquatted

class HttpxClient:
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def stream_get(self, url: str, headers: dict[str, str]):
        async with self.client.stream("GET", url, headers=headers) as response:
            async for chunk in response.aiter_bytes():
                yield chunk

    async def get(self, url: str, headers: dict[str, str]):
        response = await self.client.get(url, headers=headers)
        return response.content, response.headers

client = HaveIBeenSquatted("ak_your_api_key", http_client=HttpxClient())
```

## Error handling

```python
from haveibeensquatted import HTTPError, URLError, RateLimitError

try:
    async for message in client.squat("example.com"):
        pass
except RateLimitError as e:
    print(f"Rate limited: {e.retry_after}s")
except HTTPError as e:
    # HTTP 401: API key expired, revoked, or invalid
    # HTTP 403: API key missing required scope for this endpoint
    # HTTP 429: Rate limit exceeded (use RateLimitError instead)
    print(f"HTTP error: {e}")
except URLError as e:
    print(f"Network error: {e}")
except ValueError as e:
    print(f"Invalid input: {e}")
```

### API Key Scopes

API keys can be restricted to specific scopes. Each endpoint requires a specific scope

- `lookup:squat` - Required for `squat()` method
- `lookup:nxdomain` - Required for `nxdomain()` method
- `analyze` - Required for `analyze()` method
- `ct` - Required for `ct_search()`, `ct_search_domains()`, and `ct_hydrate()` methods

If your API key doesn't have the required scope, you'll receive HTTP 403 Forbidden.

### API Key Expiry

API keys can expire. If your API key has expired, you'll receive HTTP 401 Unauthorized. Check your API key expiration date in your account settings.

## Examples

Check out the `examples/` directory for complete CLI tools

- `lookup.py` - Domain squatting analysis with progress tracking
- `nxdomain.py` - Unregistered domain discovery with filtering
- `analyze.py` - Comprehensive domain analysis with detailed output
- `ct_search.py` - Certificate transparency search and hydration
- `usage.py` - Usage metrics

Run an example:

```bash
export HIBS_API_KEY="ak_your_api_key"
python examples/lookup.py example.com
```

## Data models

```python
from haveibeensquatted import (
    Message,
    PermutationResult,
    LookupEvent,
    GeoIpData,
    Classification,
    DnsRecords,
)
```

## Pydantic integration

You can validate SDK dataclasses with Pydantic v2 using a `TypeAdapter`

```python
from pydantic import TypeAdapter
from haveibeensquatted.models import CTSearchResult

adapter = TypeAdapter(CTSearchResult)
result = adapter.validate_python(payload_dict)
```

Or wrap SDK dataclasses in your own `BaseModel`

```python
from pydantic import BaseModel, ConfigDict
from haveibeensquatted.models import UsageResponse

class UsageWrapper(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    usage: UsageResponse

wrapped = UsageWrapper.model_validate({"usage": payload_dict})
```

## Development

```bash
git clone https://github.com/haveibeensquatted/haveibeensquatted-python.git
cd haveibeensquatted-python
uv sync
uv run pytest
uv run ruff check
```

## API reference

For detailed API documentation, see the [Have I Been Squatted API docs](https://docs.haveibeensquatted.com/guides/api/).

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- Email: [hello@haveibeensquatted.com](mailto:hello@haveibeensquatted.com)
- Documentation: [docs.haveibeensquatted.com](https://docs.haveibeensquatted.com)
- Issues: [GitHub Issues](https://github.com/haveibeensquatted/haveibeensquatted-python/issues)
