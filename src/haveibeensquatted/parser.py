"""Streaming JSON parser for Have I Been Squatted API responses.

This module provides functionality to parse streaming JSON responses from the
Have I Been Squatted API and convert them into structured Python objects.
"""

import json
from collections.abc import AsyncIterator, Mapping

from .models import (
    CertificateDetails,
    Classification,
    CTSearchResult,
    DnsRecords,
    Domain,
    GeoIpAsn,
    GeoIpCountry,
    GeoIpData,
    HourlyUsage,
    HydratedOccurrenceResult,
    HydrateItem,
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


def _strip_nulls_in_dicts(value: object) -> object:
    """Recursively remove keys with None values from dicts; leave lists and primitives intact.

    This function is used to clean up data structures before serialization,
    particularly for compatibility with systems that don't handle null values well.

    Args:
        value: The value to process (dict, list, or primitive)

    Returns:
        The cleaned value with None keys removed from dicts
    """
    if isinstance(value, list):
        return [_strip_nulls_in_dicts(v) for v in value]
    if isinstance(value, Mapping):
        cleaned: dict[str, object] = {}
        for k, v in value.items():
            if v is None:
                continue
            cleaned[k] = _strip_nulls_in_dicts(v)
        return cleaned
    return value


class StreamParser:
    """Parser for streaming JSON responses from Have I Been Squatted API.

    This parser handles the real-time streaming of JSON messages from the API,
    converting them into structured Python objects. It maintains a buffer to
    handle partial messages and provides methods to merge related messages
    into complete results.

    Example:
        ```python
        parser = StreamParser()
        async for message in parser.parse_stream(byte_iterator):
            if message.op == Operation.META:
                print(f"Progress: {message.data}")
            elif message.op == Operation.GEO_IP:
                print(f"Found IP: {message.data.ip}")
        ```
    """

    def __init__(self) -> None:
        """Initialize the stream parser."""
        self.buffer: bytes = b""
        self.bytes_received: int = 0

    async def parse_stream(self, byte_iterator: AsyncIterator[bytes]) -> AsyncIterator[Message]:
        """Parse a stream of bytes into Message objects.

        Args:
            byte_iterator: Async iterator yielding bytes from the API response

        Yields:
            Parsed Message objects from the stream

        Note:
            Malformed JSON messages are silently skipped to maintain
            streaming performance.
        """
        async for chunk in byte_iterator:
            self.buffer += chunk
            self.bytes_received += len(chunk)

            # Process complete lines
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)

                if line.strip():
                    try:
                        parsed_data = json.loads(line)
                        message = self._parse_message(parsed_data)
                        if message:
                            yield message
                    except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                        # Skip malformed messages
                        continue

        # Process any remaining buffer content
        if self.buffer.strip():
            try:
                parsed_data = json.loads(self.buffer)
                message = self._parse_message(parsed_data)
                if message:
                    yield message
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                pass

    def _parse_message(self, data: Mapping[str, object]) -> Message | None:
        """Parse a single JSON object into a Message.

        Args:
            data: The JSON data as a mapping

        Returns:
            Parsed Message object, or None if parsing fails
        """
        try:
            op = Operation(data["op"])  # type: ignore[arg-type]
        except (KeyError, ValueError, TypeError):
            return None

        # Parse permutation if present
        permutation: Permutation | None = None
        perm_raw = data.get("permutation")
        if isinstance(perm_raw, Mapping):
            permutation = self._parse_permutation(perm_raw)
            if permutation is None:
                return None

        # Parse data based on operation type
        parsed_data = self._parse_operation_data(op, data.get("data"))

        return Message(op=op, permutation=permutation, data=parsed_data)

    def _parse_operation_data(self, op: Operation, data: object) -> object:  # noqa: PLR0911
        """Parse operation-specific data based on the operation type.

        Args:
            op: The operation type
            data: The raw data to parse

        Returns:
            Parsed data object

        Raises:
            TypeError: If the data format is invalid for the operation
        """
        if data is None:
            return None

        if op == Operation.GEO_IP:
            if not isinstance(data, Mapping):
                raise TypeError("GeoIp expects object")
            geo = self._parse_geo_ip(data)
            if geo is None:
                raise TypeError("Invalid GeoIp payload")
            return geo
        if op == Operation.CLASSIFICATION:
            if not isinstance(data, Mapping):
                raise TypeError("Classification expects object")
            cls = self._parse_classification(data)
            if cls is None:
                raise TypeError("Invalid Classification payload")
            return cls
        if op == Operation.META:
            if not isinstance(data, Mapping):
                raise TypeError("Meta expects object")
            return self._parse_meta(data)
        if op == Operation.REDIRECT_CHAIN:
            return self._parse_redirect_chain(data)
        if op == Operation.DNS:
            if not isinstance(data, Mapping):
                raise TypeError("DNS expects object")
            return self._parse_dns(data)
        if op == Operation.MX_CHECK:
            if not isinstance(data, Mapping):
                raise TypeError("MxCheck expects object")
            return self._parse_smtp_metadata(data)
        if op == Operation.NXDOMAIN:
            if not isinstance(data, Mapping):
                raise TypeError("Nxdomain expects object")
            return self._parse_nxdomain_metadata(data)
        if op == Operation.ORIGIN_X509:
            if not isinstance(data, Mapping):
                raise TypeError("OriginX509 expects object")
            return self._parse_x509_certificate(data)
        if op == Operation.PASSIVE_DNS:
            if not isinstance(data, list):
                raise TypeError("PassiveDns expects list")
            return self._parse_passive_dns(data)
        if op == Operation.PASSIVE_TLS:
            if not isinstance(data, Mapping):
                raise TypeError("PassiveTls expects object")
            return self._parse_passive_tls(data)
        if op == Operation.CERTIFICATE_TRANSPARENCY:
            if not isinstance(data, Mapping):
                raise TypeError("CertificateTransparency expects object")
            return self._parse_ct_search_result(data)
        # Other ops can be primitive or lists; accept as-is
        return data

    def _parse_permutation(self, perm_raw: Mapping[str, object]) -> Permutation | None:
        """Parse permutation data from JSON.

        Args:
            perm_raw: Raw permutation data from JSON

        Returns:
            Parsed Permutation object, or None if parsing fails
        """
        domain_raw = perm_raw.get("domain")
        if not isinstance(domain_raw, Mapping):
            return None
        try:
            domain = Domain(
                fqdn=str(domain_raw.get("fqdn")),
                tld=str(domain_raw.get("tld")),
                domain=str(domain_raw.get("domain")),
            )
            return Permutation(domain=domain, kind=PermutationKind(str(perm_raw.get("kind"))))
        except Exception:
            return None

    def _parse_geo_ip(self, data: Mapping[str, object]) -> GeoIpData | None:
        """Parse GeoIP data from JSON.

        Args:
            data: Raw GeoIP data from JSON

        Returns:
            Parsed GeoIpData object, or None if parsing fails
        """
        asn_raw = data.get("asn")
        country_raw = data.get("country")
        ip = data.get("ip")
        if not isinstance(ip, str):
            return None
        asn: GeoIpAsn | None = None
        country: GeoIpCountry | None = None
        if isinstance(asn_raw, Mapping):
            asn = GeoIpAsn(
                number=_optional_int(asn_raw.get("number")),
                organization=_optional_str(asn_raw.get("organization")),
            )
        if isinstance(country_raw, Mapping):
            country = GeoIpCountry(
                continent=_optional_str(country_raw.get("continent")),
                iso_code=_optional_str(country_raw.get("iso_code")),
            )
        try:
            return GeoIpData(
                ip=ip,
                asn=asn,
                country=country,
            )
        except Exception:
            return None

    def _parse_classification(self, data: Mapping[str, object]) -> Classification | None:
        """Parse classification data from JSON.

        Args:
            data: Raw classification data from JSON

        Returns:
            Parsed Classification object, or None if parsing fails
        """
        try:
            return Classification(
                legitimate=float(data.get("legitimate", 0.0)),
                phishing=float(data.get("phishing", 0.0)),
                parked=float(data.get("parked", 0.0)),
            )
        except Exception:
            return None

    def _parse_meta(self, data: Mapping[str, object]) -> MetaData:
        """Parse metadata from JSON.

        Args:
            data: Raw metadata from JSON

        Returns:
            Parsed MetaData object
        """
        kind_val = data.get("kind")
        try:
            kind = MetaKind(kind_val)  # type: ignore[arg-type]
        except Exception:
            return MetaData(kind=MetaKind.PROGRESS, data=data.get("data"))
        return MetaData(kind=kind, data=data.get("data"))

    def _parse_redirect_chain(self, data: object) -> list[Redirect]:
        """Parse redirect chain data from JSON.

        Args:
            data: Raw redirect chain data from JSON

        Returns:
            List of Redirect objects

        Raises:
            TypeError: If the data format is invalid
        """
        redirects: list[Redirect] = []
        if not isinstance(data, list):
            raise TypeError("RedirectChain expects list")
        for item in data:
            if isinstance(item, Redirect):
                redirects.append(item)
            elif isinstance(item, Mapping):
                url = item.get("url")
                # Accept either status_code or status (some producers use 'status')
                status_code = item.get("status")
                if status_code is None and "status_code" in item:
                    status_code = item.get("status_code")
                kind_raw = item.get("kind")
                kind = (
                    RedirectKind(kind_raw)
                    if isinstance(kind_raw, str)
                    else RedirectKind.INITIAL_REQUEST
                )
                cert_raw = item.get("certificate")
                certificate = (
                    self._parse_certificate_details(cert_raw)
                    if isinstance(cert_raw, Mapping)
                    else None
                )
                # Accept missing/null status from upstream
                if isinstance(url, str):
                    sc = int(status_code) if isinstance(status_code, int) else None
                    redirects.append(
                        Redirect(url=url, status=sc, kind=kind, certificate=certificate)
                    )
                else:
                    raise TypeError("Invalid Redirect entry")
            else:
                raise TypeError("Invalid Redirect entry type")
        return redirects

    def _parse_dns(self, data: Mapping[str, object]) -> DnsRecords:
        """Parse DNS records from JSON.

        Args:
            data: Raw DNS data from JSON

        Returns:
            Parsed DnsRecords object

        Raises:
            TypeError: If the data format is invalid
        """

        def list_of_str(value: object, key: str) -> list[str]:
            if value is None:
                return []
            if not isinstance(value, list):
                raise TypeError(f"DNS {key} expects list")
            out: list[str] = []
            for v in value:
                if not isinstance(v, str):
                    raise TypeError(f"DNS {key} expects list[str]")
                out.append(v)
            return out

        return DnsRecords(
            a=list_of_str(data.get("a"), "a"),
            aaaa=list_of_str(data.get("aaaa"), "aaaa"),
            mx=list_of_str(data.get("mx"), "mx"),
            txt=list_of_str(data.get("txt"), "txt"),
            cname=list_of_str(data.get("cname"), "cname"),
            ns=list_of_str(data.get("ns"), "ns"),
        )

    def _parse_smtp_metadata(self, data: Mapping[str, object]) -> SmtpMetadata:
        is_positive = data.get("is_positive")
        response = data.get("response")
        if not isinstance(is_positive, bool) or not isinstance(response, str):
            raise TypeError("Invalid SMTP metadata payload")
        return SmtpMetadata(is_positive=is_positive, response=response)

    def _parse_nxdomain_metadata(self, data: Mapping[str, object]) -> NxdomainMetadata:
        query = data.get("query")
        soa = data.get("soa")
        trusted = data.get("trusted")
        if not isinstance(query, Mapping) or not isinstance(trusted, bool):
            raise TypeError("Invalid NXDOMAIN metadata payload")
        if soa is not None and not isinstance(soa, Mapping):
            raise TypeError("Invalid NXDOMAIN metadata payload")
        return NxdomainMetadata(
            query=dict(query),
            soa=dict(soa) if isinstance(soa, Mapping) else None,
            trusted=trusted,
        )

    def _parse_passive_dns(self, data: list[object]) -> list[PassiveDNSRecord]:
        records: list[PassiveDNSRecord] = []
        for entry in data:
            if not isinstance(entry, Mapping):
                raise TypeError("PassiveDns expects list[object]")
            records.append(
                PassiveDNSRecord(
                    rrtype=str(entry.get("rrtype")),
                    rrname=str(entry.get("rrname")),
                    rdata=str(entry.get("rdata")),
                    time_first=int(entry.get("time_first")),
                    time_last=int(entry.get("time_last")),
                    count=int(entry.get("count")),
                )
            )
        return records

    def _parse_passive_tls(self, data: Mapping[str, object]) -> dict[str, PassiveTLSRecord]:
        out: dict[str, PassiveTLSRecord] = {}
        for ip, value in data.items():
            if not isinstance(ip, str) or not isinstance(value, Mapping):
                raise TypeError("PassiveTls expects object mapping")
            certificates = _require_str_list(value.get("certificates"))
            subjects = _require_str_list(value.get("subjects"))
            out[ip] = PassiveTLSRecord(certificates=certificates, subjects=subjects)
        return out

    def _parse_x509_certificate(self, data: Mapping[str, object]) -> ParsedX509Certificate:
        return ParsedX509Certificate(
            fingerprint_sha256=str(data.get("fingerprint_sha256")),
            serial=str(data.get("serial")),
            subject_dn=str(data.get("subject_dn")),
            issuer_dn=str(data.get("issuer_dn")),
            not_before=int(data.get("not_before")),
            not_after=int(data.get("not_after")),
            ttl_days=int(data.get("ttl_days")),
            key_alg=str(data.get("key_alg")),
            key_size_bits=int(data.get("key_size_bits")),
            sig_alg_oid=str(data.get("sig_alg_oid")),
            san_dns=_require_str_list(data.get("san_dns")),
            san_dns_count=int(data.get("san_dns_count")),
            san_ip=_require_str_list(data.get("san_ip")),
            is_ca=bool(data.get("is_ca")),
            path_len=_optional_int(data.get("path_len")),
            policy_oids=_require_str_list(data.get("policy_oids")),
            ocsp_uris=_require_str_list(data.get("ocsp_uris")),
            crl_dp=_require_str_list(data.get("crl_dp")),
        )

    def _parse_certificate_details(self, data: Mapping[str, object]) -> CertificateDetails:
        return CertificateDetails(
            subject_name=str(data.get("subject_name")),
            san_list=_require_str_list(data.get("san_list")),
            issuer=str(data.get("issuer")),
            valid_from=float(data.get("valid_from")),
            valid_to=float(data.get("valid_to")),
            certificate_transparency_compliance=str(
                data.get("certificate_transparency_compliance")
            ),
            certificate_id=int(data.get("certificate_id")),
            signed_certificate_timestamp_list=list(
                data.get("signed_certificate_timestamp_list", [])
            ),
            key_exchange_group=_optional_str(data.get("key_exchange_group")),
            mac=_optional_str(data.get("mac")),
            protocol=str(data.get("protocol")),
            key_exchange=str(data.get("key_exchange")),
            cipher=str(data.get("cipher")),
        )

    def _parse_occurrence_result(
        self, data: Mapping[str, object]
    ) -> OccurrenceRec | HydratedOccurrenceResult:
        if "cert" in data:
            cert_raw = data.get("cert")
            if not isinstance(cert_raw, Mapping):
                raise TypeError("Hydrated occurrence cert must be object")
            cert = self._parse_x509_certificate(cert_raw)
            occ = OccurrenceRec(
                log_id=int(data.get("log_id")),
                kind=int(data.get("kind")),
                ts_sec=int(data.get("ts_sec")),
                index=int(data.get("index")),
            )
            return HydratedOccurrenceResult(occ=occ, cert=cert)
        return OccurrenceRec(
            log_id=int(data.get("log_id")),
            kind=int(data.get("kind")),
            ts_sec=int(data.get("ts_sec")),
            index=int(data.get("index")),
        )

    def _parse_ct_search_result(self, data: Mapping[str, object]) -> CTSearchResult:
        labels_raw = data.get("labels")
        if not isinstance(labels_raw, Mapping):
            raise TypeError("CTSearchResult labels must be object")
        labels = SearchResultLabels(
            tld=str(labels_raw.get("tld")),
            etld1=str(labels_raw.get("etld1")),
            domain=str(labels_raw.get("domain")),
            registrable_domain=_optional_str(labels_raw.get("registrable_domain")),
            subdomain=_optional_str(labels_raw.get("subdomain")),
        )
        occurrences_raw = data.get("occurrences")
        occurrences: list[OccurrenceRec | HydratedOccurrenceResult] | None = None
        if isinstance(occurrences_raw, list):
            occurrences = []
            for occ in occurrences_raw:
                if not isinstance(occ, Mapping):
                    raise TypeError("CT occurrences must be objects")
                parsed = self._parse_occurrence_result(occ)
                occurrences.append(parsed)
        cert_raw = data.get("cert")
        cert = self._parse_x509_certificate(cert_raw) if isinstance(cert_raw, Mapping) else None
        return CTSearchResult(
            name=str(data.get("name")),
            labels=labels,
            is_precert=bool(data.get("is_precert")),
            log_id=_optional_int(data.get("log_id")),
            index=_optional_int(data.get("index")),
            occurrences_count=_optional_int(data.get("occurrences_count")),
            last_seen_ts=_optional_int(data.get("last_seen_ts")),
            occurrences=occurrences,
            cert=cert,
        )

    def _parse_hydrate_item(self, data: Mapping[str, object]) -> HydrateItem:
        cert_raw = data.get("cert")
        cert = self._parse_x509_certificate(cert_raw) if isinstance(cert_raw, Mapping) else None
        error = data.get("error")
        return HydrateItem(
            log_id=int(data.get("log_id")),
            index=int(data.get("index")),
            cert=cert,
            error=str(error) if isinstance(error, str) else None,
        )

    def _parse_usage_response(self, data: object) -> UsageResponse:
        if not isinstance(data, Mapping):
            raise TypeError("Usage response must be object")
        period_raw = data.get("period")
        totals_raw = data.get("totals")
        hourly_raw = data.get("hourly")
        if not isinstance(period_raw, Mapping) or not isinstance(totals_raw, Mapping):
            raise TypeError("Usage response invalid")
        period = UsagePeriod(
            start=str(period_raw.get("start")),
            end=str(period_raw.get("end")),
        )
        totals = UsageTotals(
            lookup_requests=int(totals_raw.get("lookup_requests")),
            ct_requests=int(totals_raw.get("ct_requests")),
            total_requests=int(totals_raw.get("total_requests")),
        )
        hourly: list[HourlyUsage] = []
        if isinstance(hourly_raw, list):
            for entry in hourly_raw:
                if not isinstance(entry, Mapping):
                    raise TypeError("Hourly usage must be objects")
                hourly.append(
                    HourlyUsage(
                        timestamp=str(entry.get("timestamp")),
                        lookup_requests=int(entry.get("lookup_requests")),
                        ct_requests=int(entry.get("ct_requests")),
                    )
                )
        return UsageResponse(period=period, totals=totals, hourly=hourly)

    def merge_messages(self, _domain: str, messages: list[Message]) -> PermutationResult | None:
        """Merge a list of messages for a domain into a single PermutationResult.

        Args:
            _domain: The domain name (for reference, currently unused)
            messages: List of messages to merge

        Returns:
            Merged PermutationResult object, or None if no valid messages
        """
        if not messages:
            return None

        # Find the first message with a permutation to get basic info
        base_permutation: Permutation | None = None
        for msg in messages:
            if msg.permutation:
                base_permutation = msg.permutation
                break

        if not base_permutation:
            return None

        result = PermutationResult(permutation=base_permutation)

        # Merge all operation data (types were validated at parse time)
        ips_dict: dict[str, GeoIpData | None] = {}

        for msg in messages:
            if msg.op == Operation.META:
                continue
            elif msg.op == Operation.LEVENSHTEIN:
                result.distance = int(msg.data)  # type: ignore[arg-type]
            elif msg.op == Operation.IP_ENUMERATION:
                for ip in msg.data:  # type: ignore[assignment]
                    if ip not in ips_dict:
                        ips_dict[ip] = None  # type: ignore[index]
            elif msg.op == Operation.GEO_IP:
                if msg.data.ip:  # type: ignore[union-attr]
                    ips_dict[msg.data.ip] = msg.data  # type: ignore[index]
            elif msg.op == Operation.HTTP_BANNER:
                result.http_banner = str(msg.data)
            elif msg.op == Operation.RDAP:
                result.rdap = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.WHOIS:
                result.whois = msg.data
            elif msg.op == Operation.CLASSIFICATION:
                result.classification = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.TECHNOLOGIES:
                result.technologies = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.SCREENSHOT:
                result.screenshot_url = str(msg.data)
            elif msg.op == Operation.REDIRECT_CHAIN:
                if isinstance(msg.data, list) and all(isinstance(x, Redirect) for x in msg.data):
                    result.redirect_chain = msg.data  # type: ignore[assignment]
                else:
                    redirects = self._parse_redirect_chain(msg.data)
                    if redirects:
                        result.redirect_chain = redirects
            elif msg.op == Operation.DNS:
                if isinstance(msg.data, DnsRecords):
                    dns = msg.data
                elif isinstance(msg.data, Mapping):
                    dns = self._parse_dns(msg.data)
                else:
                    raise TypeError("DNS expected DnsRecords or object")
                result.dns_a = dns.a
                result.dns_aaaa = dns.aaaa
                result.dns_mx = dns.mx
                result.dns_txt = dns.txt
                result.dns_cname = dns.cname
                result.dns_ns = dns.ns
            elif msg.op == Operation.REGISTRATION_METADATA:
                result.registration_metadata = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.MX_CHECK:
                result.smtp_metadata = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.NXDOMAIN:
                result.nxdomain_metadata = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.ORIGIN_X509:
                result.origin_x509 = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.PASSIVE_DNS:
                result.passive_dns = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.PASSIVE_TLS:
                result.passive_tls = msg.data  # type: ignore[assignment]
            elif msg.op == Operation.CERTIFICATE_TRANSPARENCY:
                result.certificate_transparency = msg.data  # type: ignore[assignment]

        if ips_dict:
            # Normalize: no null map values; for missing GeoIP emit minimal struct with only ip
            normalized: dict[str, object] = {}
            for ip, geo in ips_dict.items():
                if geo is None:
                    normalized[ip] = {"ip": ip}
                else:
                    normalized[ip] = geo
            result.ips = normalized  # type: ignore[assignment]

        # Normalize redirect_chain for serialization: drop nulls generically in entries
        if result.redirect_chain:
            sanitized: list[dict[str, object]] = []
            for item in result.redirect_chain:
                if isinstance(item, Redirect):
                    entry: dict[str, object] = {
                        "url": item.url,
                        "status": item.status,
                        "kind": item.kind.value,
                    }
                    if item.certificate is not None:
                        entry["certificate"] = _strip_nulls_in_dicts(
                            dict(item.certificate.__dict__)
                        )
                    entry = _strip_nulls_in_dicts(entry)  # type: ignore[assignment]
                    sanitized.append(entry)  # type: ignore[arg-type]
                elif isinstance(item, Mapping):
                    url = item.get("url")
                    if isinstance(url, str):
                        entry = _strip_nulls_in_dicts(dict(item))  # type: ignore[arg-type]
                        sanitized.append(entry)  # type: ignore[arg-type]
                # Ignore invalid items; they would have been validated on parse
            result.redirect_chain = sanitized  # type: ignore[assignment]

        # Sanitize mapping fields to avoid maps with null values
        if isinstance(result.registration_metadata, Mapping):
            result.registration_metadata = _strip_nulls_in_dicts(result.registration_metadata)  # type: ignore[assignment]
        if isinstance(result.whois, Mapping):
            result.whois = _strip_nulls_in_dicts(result.whois)  # type: ignore[assignment]

        return result

    def merge_grouped_messages(
        self, domain_messages: Mapping[str, list[Message]]
    ) -> dict[str, PermutationResult]:
        """Merge grouped messages by domain into PermutationResult objects.

        Args:
            domain_messages: Mapping of domain names to lists of messages

        Returns:
            Dictionary mapping domain names to merged PermutationResult objects
        """
        merged: dict[str, PermutationResult] = {}
        for perm_domain, msgs in domain_messages.items():
            merged_result = self.merge_messages(perm_domain, msgs)
            if merged_result:
                merged[perm_domain] = merged_result
        return merged


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _require_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError("Expected list of strings")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError("Expected list of strings")
        out.append(item)
    return out
