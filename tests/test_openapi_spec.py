from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import yaml
from openapi_spec_validator import validate

SPEC_PATH = Path(__file__).parent.parent / "docs" / "openapi.yaml"
SPEC_JSON_PATH = Path(__file__).parent.parent / "docs" / "openapi.json"


def _load_spec() -> dict[str, object]:
    with SPEC_PATH.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert isinstance(data, dict)
    return data


def _resolve_local_refs(value: object, spec: dict[str, object]) -> object:
    if isinstance(value, list):
        return [_resolve_local_refs(item, spec) for item in value]

    if not isinstance(value, dict):
        return value

    if "$ref" in value:
        ref = value["$ref"]
        assert isinstance(ref, str)
        assert ref.startswith("#/components/schemas/")
        schema_name = ref.rsplit("/", 1)[-1]
        components = spec["components"]
        assert isinstance(components, dict)
        schemas = components["schemas"]
        assert isinstance(schemas, dict)
        return _resolve_local_refs(deepcopy(schemas[schema_name]), spec)

    return {key: _resolve_local_refs(item, spec) for key, item in value.items()}


def _validate_example(schema: object, example: object, spec: dict[str, object]) -> None:
    resolved_schema = _resolve_local_refs(deepcopy(schema), spec)
    jsonschema.Draft202012Validator.check_schema(resolved_schema)
    jsonschema.Draft202012Validator(resolved_schema).validate(example)


def _resolve_parameter(parameter: object, spec: dict[str, object]) -> dict[str, object]:
    assert isinstance(parameter, dict)
    if "$ref" not in parameter:
        return parameter

    ref = parameter["$ref"]
    assert isinstance(ref, str)
    assert ref.startswith("#/components/parameters/")
    parameter_name = ref.rsplit("/", 1)[-1]
    components = spec["components"]
    assert isinstance(components, dict)
    parameters = components["parameters"]
    assert isinstance(parameters, dict)
    resolved = parameters[parameter_name]
    assert isinstance(resolved, dict)
    return resolved


def test_openapi_version_and_expected_paths() -> None:
    spec = _load_spec()

    assert spec["openapi"] == "3.1.1"

    paths = spec["paths"]
    assert isinstance(paths, dict)
    assert set(paths) == {
        "/lookup/squat/{domain}",
        "/lookup/nxdomain/{domain}",
        "/analyze/{domain}",
        "/ct/search",
        "/ct/search/domains",
        "/ct/hydrate",
        "/meta/usage",
    }


def test_openapi_json_matches_yaml_and_validates() -> None:
    spec_from_yaml = _load_spec()
    validate(spec_from_yaml)
    with SPEC_JSON_PATH.open("r", encoding="utf-8") as handle:
        spec_from_json: dict[str, object] = json.load(handle)
    assert spec_from_json == spec_from_yaml
    validate(spec_from_json)


def test_bearer_auth_is_defined() -> None:
    spec = _load_spec()

    components = spec["components"]
    assert isinstance(components, dict)
    security_schemes = components["securitySchemes"]
    assert isinstance(security_schemes, dict)
    bearer_auth = security_schemes["bearerAuth"]
    assert isinstance(bearer_auth, dict)

    assert bearer_auth["type"] == "http"
    assert bearer_auth["scheme"] == "bearer"
    assert bearer_auth["bearerFormat"] == "API key"
    assert spec["security"] == [{"bearerAuth": []}]


def test_ct_search_is_array_plus_has_more_header() -> None:
    spec = _load_spec()

    get_op = spec["paths"]["/ct/search"]["get"]
    assert isinstance(get_op, dict)
    response = get_op["responses"]["200"]
    assert isinstance(response, dict)

    headers = response["headers"]
    assert isinstance(headers, dict)
    assert "X-Has-More-Value" in headers
    header_ref = headers["X-Has-More-Value"]["$ref"]
    assert header_ref == "#/components/headers/XHasMoreValue"

    components = spec["components"]
    assert isinstance(components, dict)
    header_schema = components["headers"]["XHasMoreValue"]["schema"]
    assert isinstance(header_schema, dict)
    assert header_schema["type"] == "string"
    assert header_schema["enum"] == ["true", "false"]

    content = response["content"]
    assert isinstance(content, dict)
    schema = content["application/json"]["schema"]
    assert isinstance(schema, dict)
    assert schema["type"] == "array"
    assert "results" not in schema.get("properties", {})


def test_ct_search_domains_and_hydrate_do_not_advertise_pagination() -> None:
    spec = _load_spec()
    forbidden_params = {"page", "cursor", "offset"}

    for path in ("/ct/search/domains", "/ct/hydrate"):
        get_op = spec["paths"][path]["get"]
        assert isinstance(get_op, dict)
        params = get_op["parameters"]
        assert isinstance(params, list)
        names = {_resolve_parameter(param, spec)["name"] for param in params}
        assert forbidden_params.isdisjoint(names)


def test_live_query_parameter_constraints_are_documented() -> None:
    spec = _load_spec()
    components = spec["components"]
    assert isinstance(components, dict)
    parameters = components["parameters"]
    assert isinstance(parameters, dict)

    ct_kind = parameters["CtKind"]["schema"]
    assert ct_kind["enum"] == ["regex"]

    ct_limit = parameters["CtLimit"]["schema"]
    assert ct_limit["minimum"] == 1
    assert ct_limit["maximum"] == 1000

    ct_field = parameters["CtField"]["schema"]
    assert set(ct_field["enum"]) == {
        "domain_raw",
        "domain_ngram",
        "ngram",
    }

    usage_window = parameters["UsageWindow"]["schema"]
    assert usage_window["minimum"] == 60
    assert usage_window["maximum"] == 129600


def test_streaming_lookup_endpoints_are_ndjson_and_use_discriminator() -> None:
    spec = _load_spec()
    components = spec["components"]
    assert isinstance(components, dict)
    schemas = components["schemas"]
    assert isinstance(schemas, dict)

    operation = schemas["Operation"]
    assert isinstance(operation, dict)
    assert "Meta" in operation["enum"]
    assert "GeoIp" in operation["enum"]
    assert "CertificateTransparency" in operation["enum"]
    assert {
        "DomainStatus",
        "PageRank",
        "Identifiers",
        "Subdomains",
        "TlsChain",
        "Sitemap",
        "CrawlMeta",
        "BusinessIntel",
        "Ports",
        "Security",
        "DomainMetadata",
    }.issubset(operation["enum"])

    stream_base = schemas["StreamMessageBase"]
    assert isinstance(stream_base, dict)
    base_properties = stream_base["properties"]
    assert isinstance(base_properties, dict)
    assert base_properties["op"]["$ref"] == "#/components/schemas/Operation"

    stream_message = schemas["StreamMessage"]
    assert isinstance(stream_message, dict)
    discriminator = stream_message["discriminator"]
    assert isinstance(discriminator, dict)
    assert discriminator["propertyName"] == "op"
    assert discriminator["mapping"]["GeoIp"] == "#/components/schemas/GeoIpStreamMessage"
    assert discriminator["mapping"]["Dns"] == "#/components/schemas/DnsStreamMessage"
    assert discriminator["mapping"]["Levenshtein"] == "#/components/schemas/GenericStreamMessage"

    geo_ip_variant = schemas["GeoIpStreamMessage"]
    assert isinstance(geo_ip_variant, dict)
    geo_ip_variant_schema = _resolve_local_refs(geo_ip_variant, spec)
    assert isinstance(geo_ip_variant_schema, dict)
    geo_ip_data = geo_ip_variant_schema["allOf"][1]["properties"]["data"]
    assert geo_ip_data["oneOf"][1]["type"] == "null"
    assert geo_ip_data["oneOf"][0]["required"] == ["ip"]

    dns_variant = schemas["DnsStreamMessage"]
    assert isinstance(dns_variant, dict)
    dns_variant_schema = _resolve_local_refs(dns_variant, spec)
    assert isinstance(dns_variant_schema, dict)
    dns_data = dns_variant_schema["allOf"][1]["properties"]["data"]
    assert dns_data["oneOf"][0]["type"] == "object"

    generic_variant = schemas["GenericStreamMessage"]
    assert isinstance(generic_variant, dict)
    generic_variant_schema = _resolve_local_refs(generic_variant, spec)
    assert isinstance(generic_variant_schema, dict)
    generic_ops = generic_variant_schema["allOf"][1]["properties"]["op"]["enum"]
    assert "Levenshtein" in generic_ops
    assert "RegistrationMetadata" in generic_ops
    assert "DomainMetadata" in generic_ops
    assert "Security" in generic_ops

    for path in (
        "/lookup/squat/{domain}",
        "/lookup/nxdomain/{domain}",
        "/analyze/{domain}",
    ):
        get_op = spec["paths"][path]["get"]
        assert isinstance(get_op, dict)
        response = get_op["responses"]["200"]
        assert isinstance(response, dict)
        assert "one line" in response["description"]
        assert response["x-line-delimited"] is True

        content = response["content"]
        assert isinstance(content, dict)
        assert "application/x-ndjson" in content

        media_type = content["application/x-ndjson"]
        schema = media_type["schema"]
        assert isinstance(schema, dict)
        assert schema == {"$ref": "#/components/schemas/StreamMessage"}

        example = media_type["examples"]["sample"]["value"]
        assert not isinstance(example, list)
        _validate_example(schema, example, spec)


def test_dns_and_certificate_schemas_are_not_overly_strict() -> None:
    spec = _load_spec()
    components = spec["components"]
    assert isinstance(components, dict)
    schemas = components["schemas"]
    assert isinstance(schemas, dict)

    dns_records = schemas["DnsRecords"]
    assert isinstance(dns_records, dict)
    assert "required" not in dns_records
    assert {
        "a",
        "aaaa",
        "mx",
        "txt",
        "cname",
        "ns",
        "svcb",
        "https",
        "caa",
        "tlsa",
        "srv",
        "naptr",
        "ptr",
        "dnskey",
        "ds",
    } == set(dns_records["properties"])

    certificate_details = schemas["CertificateDetails"]
    assert isinstance(certificate_details, dict)
    required_fields = set(certificate_details["required"])
    assert "subject_name" in required_fields
    assert "san_list" in required_fields
    assert "issuer" in required_fields
    assert "valid_from" in required_fields
    assert "valid_to" in required_fields
    assert "certificate_transparency_compliance" in required_fields
    assert "certificate_id" in required_fields
    assert "signed_certificate_timestamp_list" not in required_fields
    assert "protocol" not in required_fields
    assert "key_exchange" not in required_fields
    assert "cipher" not in required_fields


def test_examples_validate_against_selected_schemas() -> None:
    spec = _load_spec()
    paths = spec["paths"]
    assert isinstance(paths, dict)

    ct_search_schema = paths["/ct/search"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    ct_search_example = paths["/ct/search"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["examples"]["sampleResults"]["value"]
    _validate_example(ct_search_schema, ct_search_example, spec)

    usage_schema = paths["/meta/usage"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    usage_example = paths["/meta/usage"]["get"]["responses"]["200"]["content"]["application/json"][
        "examples"
    ]["sampleUsage"]["value"]
    _validate_example(usage_schema, usage_example, spec)
