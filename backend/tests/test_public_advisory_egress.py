import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from app import public_advisory_egress as public_advisory_egress_module
from app.config import (
    DEFAULT_PUBLIC_ADVISORY_EGRESS_ENABLED,
    DEFAULT_PUBLIC_ADVISORY_NVD_ENABLED,
    DEFAULT_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS,
    DEFAULT_PUBLIC_ADVISORY_CACHE_TTL_SECONDS,
    DEFAULT_PUBLIC_ADVISORY_MAX_BATCH_COMPONENTS,
    DEFAULT_PUBLIC_ADVISORY_MAX_CONCURRENCY,
    DEFAULT_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES,
    DEFAULT_PUBLIC_ADVISORY_MAX_RETRIES,
    DEFAULT_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES,
    DEFAULT_PUBLIC_ADVISORY_PUBLIC_GO_MODULES,
    DEFAULT_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES,
    DEFAULT_PUBLIC_ADVISORY_TIMEOUT_SECONDS,
    load_settings,
)
from app.public_advisory_egress import (
    CISA_KEV_FEED_URL,
    GITHUB_GLOBAL_ADVISORIES_URL,
    NVD_CVE_API_URL,
    MAX_OSV_QUERYBATCH_PAGES,
    MAX_OSV_VULNERABILITIES_PER_PAGE,
    OSV_QUERYBATCH_URL,
    OSV_VULNERABILITY_URL_PREFIX,
    PublicAdvisoryEgressClient,
    PublicAdvisoryNamespacePolicy,
    PublicAdvisoryResponseCache,
    PublicComponentIdentity,
    normalize_osv_component_identity,
    public_advisory_cache_key,
)


def advisory_client(
    *,
    enabled=True,
    nvd_enabled=False,
    transport=None,
    cache=None,
    max_response_bytes=1024,
    max_retries=1,
    namespace_policy=None,
):
    return PublicAdvisoryEgressClient(
        enabled=enabled,
        nvd_enabled=nvd_enabled,
        timeout_seconds=1,
        max_response_bytes=max_response_bytes,
        max_concurrency=1,
        max_retries=max_retries,
        max_batch_components=2,
        namespace_policy=namespace_policy,
        http_transport=transport,
        cache=cache,
        sleep=lambda _: None,
    )


def test_public_advisory_egress_is_disabled_by_default_without_constructing_transport():
    client = advisory_client(enabled=False)

    result = client.query_osv_batch([PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")])

    assert result.status == "disabled"
    assert result.attempts == 0
    assert result.body is None


def test_nvd_is_independently_disabled_by_default_and_uses_only_an_exact_cve_when_enabled():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"format": "NVD_CVE", "version": "2.0", "totalResults": 0, "vulnerabilities": []})

    disabled = advisory_client(transport=httpx.MockTransport(handler))
    assert disabled.fetch_nvd_cve("CVE-2025-1234").status == "disabled"
    assert requests == []

    enabled = advisory_client(nvd_enabled=True, transport=httpx.MockTransport(handler))
    assert enabled.fetch_nvd_cve("cve-2025-1234").status == "success"
    assert enabled.fetch_nvd_cve("CVE-2025-1234?cpeName=private").status == "invalid_request"
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert str(requests[0].url.copy_remove_param("cveId")) == NVD_CVE_API_URL
    assert dict(requests[0].url.params) == {"cveId": "CVE-2025-1234"}
    assert requests[0].content == b""


def test_nvd_rejects_a_mismatched_cve_before_it_can_enter_the_cache(tmp_path):
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "format": "NVD_CVE",
                "version": "2.0",
                "totalResults": 1,
                "vulnerabilities": [{"cve": {"id": "CVE-2025-9999"}}],
            },
        )

    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, max_response_bytes=10_000)
    client = advisory_client(
        nvd_enabled=True,
        transport=httpx.MockTransport(handler),
        cache=cache,
        max_retries=0,
    )

    first = client.fetch_nvd_cve("CVE-2025-1234")
    second = client.fetch_nvd_cve("CVE-2025-1234")

    assert first.status == second.status == "invalid_source_response"
    assert first.body is second.body is None
    assert calls == 2
    assert cache.get(
        "nvd",
        public_advisory_cache_key("nvd", [{"cve_id": "CVE-2025-1234"}]),
    ) is None


def test_operational_cache_summary_is_aggregate_bounded_and_never_exposes_keys_or_bodies(tmp_path):
    observed = datetime(2026, 9, 9, 10, 0, tzinfo=timezone.utc)
    cache = PublicAdvisoryResponseCache(
        tmp_path, ttl_seconds=10, retention_seconds=100, max_response_bytes=10_000, clock=lambda: observed,
    )
    fresh_key = public_advisory_cache_key("osv", [{"name": "private-canary"}])
    stale_key = public_advisory_cache_key("osv", [{"name": "other-canary"}])
    cache.put("osv", fresh_key, b'{"results":[]}', now=observed)
    cache.put("osv", stale_key, b'{"results":[]}', now=observed - timedelta(seconds=20))
    invalid_key = "a" * 64
    (tmp_path / "nvd").mkdir()
    (tmp_path / "nvd" / f"{invalid_key}.json").write_text("not-json", encoding="utf-8")

    summary = {item.provider: item for item in cache.operational_summary(now=observed)}

    assert (summary["osv"].entries, summary["osv"].fresh_entries, summary["osv"].stale_entries) == (2, 1, 1)
    assert summary["nvd"].invalid_entries == 1
    rendered = repr(summary)
    assert fresh_key not in rendered
    assert stale_key not in rendered
    assert "private-canary" not in rendered
    assert "other-canary" not in rendered


def test_osv_payload_is_minimal_fixed_https_and_has_no_project_or_source_metadata():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"results": [{"vulns": []}, {"vulns": []}]})

    client = advisory_client(
        transport=httpx.MockTransport(handler),
        namespace_policy=PublicAdvisoryNamespacePolicy(public_pypi_packages=("requests-library",)),
    )
    result = client.query_osv_batch(
        [
            PublicComponentIdentity(ecosystem="npm", name="React", version="18.3.1"),
            PublicComponentIdentity(ecosystem="pypi", name="Requests._Library", version="2.32.0"),
        ]
    )

    assert result.status == "success"
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == OSV_QUERYBATCH_URL
    assert request.headers["user-agent"] == "Inspectra-public-advisory/0.1"
    payload = json.loads(request.content)
    assert payload == {
        "queries": [
            {"package": {"ecosystem": "npm", "name": "react"}, "version": "18.3.1"},
            {"package": {"ecosystem": "PyPI", "name": "requests-library"}, "version": "2.32.0"},
        ]
    }
    rendered = json.dumps(payload)
    for forbidden in ("project", "owner", "path", "archive", "sha", "token", "secret", "source"):
        assert forbidden not in rendered.lower()


def test_organization_overlay_is_exact_narrowing_and_revalidated_before_the_batch():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [{}]})

    client = advisory_client(transport=httpx.MockTransport(handler))
    approved = client.namespace_policy.with_organization_attestations(("npm:react",))
    component = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")

    success = client.query_osv_batch(
        [component],
        namespace_policy=approved,
        organization_authorizer=lambda identity: identity.name == "react",
    )
    revoked = client.query_osv_batch(
        [component],
        namespace_policy=approved,
        organization_authorizer=lambda _: False,
    )
    unapproved = client.query_osv_batch(
        [PublicComponentIdentity(ecosystem="npm", name="react-dom", version="18.3.1")],
        namespace_policy=approved,
    )

    assert success.status == "success"
    assert revoked.status == "invalid_request"
    assert revoked.attempts == 0
    assert unapproved.status == "invalid_request"
    assert requests == [{"queries": [{"package": {"ecosystem": "npm", "name": "react"}, "version": "18.3.1"}]}]


def test_organization_overlay_cannot_broaden_operator_public_identity_policy():
    requests = []
    client = advisory_client(
        transport=httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(200, json={"results": [{}]})),
        namespace_policy=PublicAdvisoryNamespacePolicy(public_pypi_packages=("approved-package",)),
    )
    broader = PublicAdvisoryNamespacePolicy(
        public_pypi_packages=("different-package",),
        organization_public_packages=("pypi:different-package",),
        organization_attestation_required=True,
    )

    result = client.query_osv_batch(
        [PublicComponentIdentity(ecosystem="pypi", name="different-package", version="1.0.0")],
        namespace_policy=broader,
    )

    assert result.status == "invalid_request"
    assert result.attempts == 0
    assert requests == []


def test_osv_accepts_an_omitted_empty_vulnerability_list_as_a_clean_result():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"results": [{}]})

    result = advisory_client(transport=httpx.MockTransport(handler)).query_osv_batch(
        [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]
    )

    assert result.status == "success"
    assert json.loads(result.body) == {"results": [{"vulns": []}]}
    assert [(request.method, str(request.url)) for request in requests] == [("POST", OSV_QUERYBATCH_URL)]


def test_osv_hydrates_only_a_valid_provider_advisory_id_on_the_fixed_detail_route(tmp_path):
    requests = []
    advisory_id = "GHSA-AAAA-BBBB-CCCC"
    hydrated_advisory = {
        "id": advisory_id,
        "modified": "2026-09-06T10:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "react"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "18.3.2"}]}],
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": advisory_id, "modified": "2026-09-06T10:00:00Z"}]}]},
            )
        return httpx.Response(200, json=hydrated_advisory)

    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, max_response_bytes=10_000)
    client = advisory_client(cache=cache, transport=httpx.MockTransport(handler), max_response_bytes=10_000)
    result = client.query_osv_batch([PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")])

    assert result.status == "success"
    assert json.loads(result.body) == {"results": [{"vulns": [hydrated_advisory]}]}
    assert [(request.method, str(request.url)) for request in requests] == [
        ("POST", OSV_QUERYBATCH_URL),
        ("GET", f"{OSV_VULNERABILITY_URL_PREFIX}{advisory_id}"),
    ]
    assert client.query_osv_batch([PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]).cache_status == "fresh"
    assert len(requests) == 2


def test_osv_rejects_an_unsafe_or_mismatched_hydration_identifier_without_partial_success():
    requests = []

    def unsafe_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "../../private"}]}]})

    unsafe = advisory_client(transport=httpx.MockTransport(unsafe_handler), max_retries=0).query_osv_batch(
        [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]
    )
    assert unsafe.status == "invalid_source_response"
    assert len(requests) == 1

    def mismatched_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "CVE-2026-1234"}]}]})
        return httpx.Response(
            200,
            json={"id": "CVE-2026-9999", "modified": "2026-09-06T10:00:00Z", "affected": []},
        )

    mismatched = advisory_client(transport=httpx.MockTransport(mismatched_handler), max_retries=0).query_osv_batch(
        [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]
    )
    assert mismatched.status == "invalid_source_response"
    assert mismatched.body is None


def test_egress_rejects_unsafe_or_non_public_component_shapes_before_network():
    def reject_network(_: httpx.Request) -> httpx.Response:
        raise AssertionError("The egress client must reject invalid identities before a request is built.")

    client = advisory_client(transport=httpx.MockTransport(reject_network))

    result = client.query_osv_batch(
        [
            PublicComponentIdentity(ecosystem="npm", name="@private/package", version="1.2.3"),
            PublicComponentIdentity(ecosystem="npm", name="react", version="^18.0.0"),
        ]
    )

    assert result.status == "invalid_request"
    assert result.attempts == 0
    assert normalize_osv_component_identity(PublicComponentIdentity(ecosystem="npm", name="../etc/passwd", version="1.0.0")) is None
    assert normalize_osv_component_identity(PublicComponentIdentity(ecosystem="pypi", name="requests", version="1.0.0\nsecret")) is None


def test_private_namespace_rules_keep_matching_components_and_rule_values_out_of_public_egress_logs(caplog):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    policy = PublicAdvisoryNamespacePolicy.from_entries(
        ("npm:prefix:company-", "npm:exact:internal-widget", "pypi:prefix:acme-private")
    )
    client = PublicAdvisoryEgressClient(
        enabled=True,
        timeout_seconds=1,
        max_response_bytes=1024,
        max_concurrency=1,
        max_retries=0,
        max_batch_components=4,
        namespace_policy=policy,
        http_transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    )

    caplog.set_level(logging.INFO, logger="inspectra.audit")
    result = client.query_osv_batch(
        [
            PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1"),
            PublicComponentIdentity(ecosystem="npm", name="company-platform", version="1.0.0"),
            PublicComponentIdentity(ecosystem="npm", name="internal-widget", version="1.0.0"),
            PublicComponentIdentity(ecosystem="pypi", name="Acme_Private_Helper", version="1.0.0"),
        ]
    )

    assert result.status == "success"
    assert requests == [{"queries": [{"package": {"ecosystem": "npm", "name": "react"}, "version": "18.3.1"}]}]
    assert policy.excludes(PublicComponentIdentity(ecosystem="npm", name="@company/private", version="1.0.0")) is True
    assert policy.excludes(PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")) is False
    assert policy.excludes(PublicComponentIdentity(ecosystem="pypi", name="acme-private-helper", version="1.0.0")) is True
    for marker in ("company-platform", "internal-widget", "acme-private", "company-"):
        assert marker not in caplog.text


def test_response_limits_redirects_and_provider_failures_are_controlled_without_body_leaks():
    routes = [
        httpx.Response(302, headers={"location": "https://example.invalid"}),
        httpx.Response(429, text="provider diagnostic should not escape"),
        httpx.Response(200, content=b"x" * 20),
    ]

    def handler(_: httpx.Request) -> httpx.Response:
        return routes.pop(0)

    client = advisory_client(transport=httpx.MockTransport(handler), max_response_bytes=10)
    component = [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]

    assert client.query_osv_batch(component).status == "redirect_blocked"
    assert client.query_osv_batch(component).status == "rate_limited"
    oversized = client.query_osv_batch(component)
    assert oversized.status == "response_too_large"
    assert oversized.body is None


def test_osv_querybatch_continues_only_tokenized_components_and_caches_a_complete_token_free_result(tmp_path):
    requests = []
    component = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")
    second_component = PublicComponentIdentity(ecosystem="npm", name="lodash", version="4.17.21")

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "OSV-first", "affected": []}], "next_page_token": "next-page-1"},
                        {"vulns": [{"id": "OSV-second", "affected": []}]},
                    ]
                },
            )
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-follow-up", "affected": []}]}]})

    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, max_response_bytes=10_000)
    client = advisory_client(cache=cache, transport=httpx.MockTransport(handler))
    result = client.query_osv_batch([component, second_component])

    assert result.status == "success"
    assert result.pages == 2
    assert result.attempts == 2
    assert requests == [
        {
            "queries": [
                {"package": {"ecosystem": "npm", "name": "react"}, "version": "18.3.1"},
                {"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.21"},
            ]
        },
        {
            "queries": [
                {
                    "package": {"ecosystem": "npm", "name": "react"},
                    "version": "18.3.1",
                    "page_token": "next-page-1",
                }
            ]
        },
    ]
    assert result.body is not None
    merged = json.loads(result.body)
    assert merged == {
        "results": [
            {"vulns": [{"id": "OSV-first", "affected": []}, {"id": "OSV-follow-up", "affected": []}]},
            {"vulns": [{"id": "OSV-second", "affected": []}]},
        ]
    }
    assert "next-page-1" not in result.body.decode("utf-8")

    cached = client.query_osv_batch([component, second_component])
    assert cached.status == "success"
    assert cached.cache_status == "fresh"
    assert cached.pages == 2
    assert len(requests) == 2
    cached_entry = cache.get("osv", public_advisory_cache_key("osv", [
        normalize_osv_component_identity(component),
        normalize_osv_component_identity(second_component),
    ]))
    assert cached_entry is not None
    assert "next-page-1" not in cached_entry.body.decode("utf-8")


def test_osv_pagination_limit_and_follow_up_failure_are_degraded_without_partial_result():
    calls = 0

    def endless_handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"results": [{"vulns": [], "next_page_token": f"page-{calls}"}]})

    component = [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]
    exhausted = advisory_client(transport=httpx.MockTransport(endless_handler), max_retries=0).query_osv_batch(component)

    assert exhausted.status == "pagination_incomplete"
    assert exhausted.pages == MAX_OSV_QUERYBATCH_PAGES
    assert exhausted.attempts == MAX_OSV_QUERYBATCH_PAGES
    assert exhausted.body is None
    assert calls == MAX_OSV_QUERYBATCH_PAGES

    responses = [
        httpx.Response(200, json={"results": [{"vulns": [], "next_page_token": "next-page-1"}]}),
        httpx.Response(503, text="sensitive-provider-diagnostic"),
    ]
    incomplete = advisory_client(transport=httpx.MockTransport(lambda _: responses.pop(0)), max_retries=0).query_osv_batch(component)

    assert incomplete.status == "pagination_incomplete"
    assert incomplete.pages == 1
    assert incomplete.attempts == 2
    assert incomplete.body is None


def test_osv_invalid_pagination_token_or_page_shape_is_rejected_without_follow_up_request():
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"results": [{"vulns": [], "next_page_token": "https://private.example/token"}]})

    result = advisory_client(transport=httpx.MockTransport(handler), max_retries=0).query_osv_batch(
        [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]
    )

    assert result.status == "invalid_source_response"
    assert result.pages == 0
    assert result.body is None
    assert calls == 1


@pytest.mark.parametrize(
    "unsafe_endpoint",
    (
        "http://api.osv.dev/v1/querybatch",
        "https://attacker.invalid/v1/querybatch",
        "https://api.osv.dev@attacker.invalid/v1/querybatch",
        "https://api.osv.dev/v1/querybatch?sensitive-endpoint-marker=1",
        "https://api.osv.dev/v1/querybatch#sensitive-endpoint-marker",
        "https://127.0.0.1/v1/querybatch",
    ),
)
def test_internal_endpoint_regression_is_blocked_before_transport_or_telemetry(monkeypatch, caplog, unsafe_endpoint):
    calls = []

    def reject_network(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise AssertionError("An unapproved internal endpoint must never reach the transport.")

    monkeypatch.setitem(public_advisory_egress_module.PUBLIC_ADVISORY_ENDPOINTS, "osv", ("POST", unsafe_endpoint))
    caplog.set_level(logging.INFO, logger="inspectra.audit")

    result = advisory_client(transport=httpx.MockTransport(reject_network)).query_osv_batch(
        [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]
    )

    assert result.status == "source_error"
    assert result.attempts == 0
    assert calls == []
    assert "attacker.invalid" not in caplog.text
    assert "sensitive-endpoint-marker" not in caplog.text


@pytest.mark.parametrize(
    ("response_or_error", "expected_status", "expected_calls"),
    (
        (httpx.Response(400, text="sensitive-provider-diagnostic"), "provider_rejected", 1),
        (httpx.Response(503, text="sensitive-provider-diagnostic"), "unavailable", 2),
        (httpx.Response(504, text="sensitive-provider-diagnostic"), "timed_out", 2),
        (httpx.ReadTimeout("sensitive-provider-diagnostic"), "timed_out", 2),
    ),
)
def test_provider_failures_are_bounded_retried_only_when_transient_and_never_expose_body(caplog, response_or_error, expected_status, expected_calls):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if isinstance(response_or_error, Exception):
            raise response_or_error
        return httpx.Response(
            response_or_error.status_code,
            content=response_or_error.content,
            headers=response_or_error.headers,
        )

    caplog.set_level(logging.INFO, logger="inspectra.audit")
    result = advisory_client(transport=httpx.MockTransport(handler), max_retries=1).query_osv_batch(
        [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]
    )

    assert result.status == expected_status
    assert result.attempts == expected_calls
    assert result.body is None
    assert calls == expected_calls
    assert "sensitive-provider-diagnostic" not in caplog.text


@pytest.mark.parametrize(
    ("response", "expected_status"),
    [
        (
            httpx.Response(200, content=b"<html>provider-html-marker</html>", headers={"content-type": "text/html"}),
            "invalid_content_type",
        ),
        (
            httpx.Response(200, content=b'{"results": invalid-json-marker', headers={"content-type": "application/json"}),
            "invalid_source_response",
        ),
        (
            httpx.Response(200, json={"results": []}),
            "invalid_source_response",
        ),
        (
            httpx.Response(200, json={"results": [{"vulns": [{} for _ in range(MAX_OSV_VULNERABILITIES_PER_PAGE + 1)]}]}),
            "invalid_source_response",
        ),
    ],
)
def test_invalid_successful_osv_responses_are_discarded_before_cache_or_audit_logs(tmp_path, caplog, response, expected_status):
    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, max_response_bytes=50_000)
    client = advisory_client(
        cache=cache,
        max_response_bytes=50_000,
        max_retries=0,
        transport=httpx.MockTransport(lambda _: response),
    )

    caplog.set_level(logging.INFO, logger="inspectra.audit")
    result = client.query_osv_batch([PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")])

    assert result.status == expected_status
    assert result.body is None
    assert not list(tmp_path.rglob("*.json"))
    assert "provider-html-marker" not in caplog.text
    assert "invalid-json-marker" not in caplog.text


@pytest.mark.parametrize(
    ("provider_kind", "response"),
    [
        ("github", httpx.Response(200, json={"unexpected": "shape"})),
        ("cisa", httpx.Response(200, json={"unexpected": "shape"})),
    ],
)
def test_invalid_secondary_provider_roots_are_not_cached(tmp_path, provider_kind, response):
    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, max_response_bytes=1024)
    client = advisory_client(cache=cache, max_retries=0, transport=httpx.MockTransport(lambda _: response))

    result = (
        client.fetch_github_advisory("GHSA-AAAA-BBBB-CCCC")
        if provider_kind == "github"
        else client.fetch_cisa_kev_feed()
    )

    assert result.status == "invalid_source_response"
    assert result.body is None
    assert not list(tmp_path.rglob("*.json"))


def test_cisa_kev_schema_drift_is_rejected_before_cache_persistence(tmp_path):
    catalog = json.loads(
        (Path(__file__).parent / "fixtures" / "cisa" / "kev-valid.json").read_text(encoding="utf-8")
    )
    catalog["count"] += 1
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=catalog)

    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, max_response_bytes=1024 * 1024)
    client = advisory_client(
        cache=cache,
        max_response_bytes=1024 * 1024,
        max_retries=0,
        transport=httpx.MockTransport(handler),
    )

    assert client.fetch_cisa_kev_feed().status == "invalid_source_response"
    assert client.fetch_cisa_kev_feed().status == "invalid_source_response"
    assert calls == 2
    assert not list(tmp_path.rglob("*.json"))


def test_only_fixed_github_and_cisa_endpoints_can_be_called():
    requests = []
    cisa_catalog = json.loads(
        (Path(__file__).parent / "fixtures" / "cisa" / "kev-valid.json").read_text(encoding="utf-8")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[])
        return httpx.Response(200, json=cisa_catalog)

    client = advisory_client(transport=httpx.MockTransport(handler))
    assert client.fetch_github_global_advisories().status == "success"
    assert client.fetch_cisa_kev_feed().status == "success"

    assert [(request.method, str(request.url)) for request in requests] == [
        ("GET", GITHUB_GLOBAL_ADVISORIES_URL),
        ("GET", CISA_KEV_FEED_URL),
    ]


def test_github_lookup_uses_only_a_normalized_existing_ghsa_alias_and_fixed_parameters():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[])

    client = advisory_client(transport=httpx.MockTransport(handler))
    result = client.fetch_github_advisory("ghsa-aaaa-bbbb-cccc")

    assert result.status == "success"
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "GET"
    assert f"{request.url.copy_with(query=None)}" == GITHUB_GLOBAL_ADVISORIES_URL
    assert dict(request.url.params) == {"ghsa_id": "GHSA-AAAA-BBBB-CCCC", "per_page": "1"}
    assert request.content == b""
    assert request.headers["accept"] == "application/vnd.github+json"
    assert request.headers["x-github-api-version"] == "2022-11-28"

    rejected = client.fetch_github_advisory("https://attacker.invalid/?ghsa_id=GHSA-aaaa-bbbb-cccc")
    assert rejected.status == "invalid_request"
    assert len(requests) == 1


def test_transport_retries_only_controlled_transient_failures():
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("controlled fixture failure")
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    result = advisory_client(transport=httpx.MockTransport(handler), max_retries=1).query_osv_batch(
        [PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")]
    )

    assert result.status == "success"
    assert result.attempts == 2
    assert calls == 2


def test_public_advisory_configuration_defaults_to_disabled_and_rejects_unsafe_bounds(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()

    assert settings.public_advisory_egress_enabled is DEFAULT_PUBLIC_ADVISORY_EGRESS_ENABLED
    assert settings.public_advisory_nvd_enabled is DEFAULT_PUBLIC_ADVISORY_NVD_ENABLED
    assert settings.public_advisory_timeout_seconds == DEFAULT_PUBLIC_ADVISORY_TIMEOUT_SECONDS
    assert settings.public_advisory_max_response_bytes == DEFAULT_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES
    assert settings.public_advisory_max_concurrency == DEFAULT_PUBLIC_ADVISORY_MAX_CONCURRENCY
    assert settings.public_advisory_max_retries == DEFAULT_PUBLIC_ADVISORY_MAX_RETRIES
    assert settings.public_advisory_cache_ttl_seconds == DEFAULT_PUBLIC_ADVISORY_CACHE_TTL_SECONDS
    assert settings.public_advisory_cache_retention_seconds == DEFAULT_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS
    assert settings.public_advisory_max_batch_components == DEFAULT_PUBLIC_ADVISORY_MAX_BATCH_COMPONENTS
    assert settings.public_advisory_private_package_rules == DEFAULT_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES
    assert settings.public_advisory_public_pypi_packages == DEFAULT_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES
    assert settings.public_advisory_public_go_modules == DEFAULT_PUBLIC_ADVISORY_PUBLIC_GO_MODULES

    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_MAX_CONCURRENCY", "5")
    with pytest.raises(ValueError, match="INSPECTRA_PUBLIC_ADVISORY_MAX_CONCURRENCY"):
        load_settings()

    monkeypatch.delenv("INSPECTRA_PUBLIC_ADVISORY_MAX_CONCURRENCY")
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES", str(DEFAULT_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES + 1))
    with pytest.raises(ValueError, match="INSPECTRA_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES"):
        load_settings()

    monkeypatch.delenv("INSPECTRA_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES")
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_CACHE_TTL_SECONDS", "3600")
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS", "3599")
    with pytest.raises(ValueError, match="CACHE_RETENTION_SECONDS"):
        load_settings()


@pytest.mark.parametrize(
    "value",
    (
        "npm:prefix:company- , pypi:exact:Acme.Private",
        "npm:scope:@company/",
    ),
)
def test_private_namespace_rule_configuration_is_bounded_and_canonicalized(monkeypatch, tmp_path, value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES", value)

    settings = load_settings()
    policy = PublicAdvisoryEgressClient.from_settings(settings).namespace_policy

    assert policy.private_package_rules
    assert all("*" not in rule for rule in policy.private_package_rules)


@pytest.mark.parametrize(
    "value",
    (
        "npm:prefix:company-*",
        "npm:prefix:https://private.example.test/",
        "npm:scope:company",
        "npm:unknown:company",
        "npm:exact:react,",
    ),
)
def test_private_namespace_rule_configuration_rejects_wildcards_and_locator_shapes(monkeypatch, tmp_path, value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES", value)

    with pytest.raises(ValueError, match="INSPECTRA_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES"):
        load_settings()


def test_public_pypi_attestation_is_empty_by_default_bounded_and_normalized(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES", "Requests_Auth, urllib3")

    settings = load_settings()
    policy = PublicAdvisoryEgressClient.from_settings(settings).namespace_policy

    assert settings.public_advisory_public_pypi_packages == ("requests-auth", "urllib3")
    assert policy.allows_attested_public_pypi(PublicComponentIdentity(ecosystem="pypi", name="requests.auth", version="2.32.3"))
    assert not policy.allows_attested_public_pypi(PublicComponentIdentity(ecosystem="pypi", name="private-package", version="1.0.0"))


def test_public_go_attestation_is_exact_and_osv_payload_contains_only_minimal_identity(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_GO_MODULES", "golang.org/x/text,github.com/public/module")
    settings = load_settings()
    policy = PublicAdvisoryEgressClient.from_settings(settings).namespace_policy
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    component = PublicComponentIdentity(ecosystem="go", name="golang.org/x/text", version="v0.19.0")
    assert settings.public_advisory_public_go_modules == ("github.com/public/module", "golang.org/x/text")
    assert policy.allows_attested_public_go(component)
    assert not policy.allows_attested_public_go(
        PublicComponentIdentity(ecosystem="go", name="private.example.test/team/mod", version="v1.0.0")
    )
    client = advisory_client(transport=httpx.MockTransport(handler), namespace_policy=policy)
    assert client.query_osv_batch([component]).status == "success"
    assert requests == [{"queries": [{"package": {"ecosystem": "Go", "name": "golang.org/x/text"}, "version": "v0.19.0"}]}]


def test_cargo_osv_payload_is_minimal_and_private_rule_fails_closed():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    component = PublicComponentIdentity(ecosystem="cargo", name="serde", version="1.0.210")
    client = advisory_client(transport=httpx.MockTransport(handler))
    assert client.query_osv_batch([component]).status == "success"
    assert requests == [{"queries": [{"package": {"ecosystem": "crates.io", "name": "serde"}, "version": "1.0.210"}]}]

    blocked = advisory_client(
        transport=httpx.MockTransport(handler),
        namespace_policy=PublicAdvisoryNamespacePolicy.from_entries(("cargo:exact:serde",)),
    )
    assert blocked.query_osv_batch([component]).status == "invalid_request"
    assert len(requests) == 1


def test_composer_attestation_is_exact_and_osv_payload_contains_only_packagist_identity(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_COMPOSER_PACKAGES", "symfony/http-foundation,psr/log")
    settings = load_settings()
    policy = PublicAdvisoryEgressClient.from_settings(settings).namespace_policy
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    component = PublicComponentIdentity(ecosystem="composer", name="symfony/http-foundation", version="7.1.3")
    assert policy.allows_attested_public_composer(component)
    assert not policy.allows_attested_public_composer(PublicComponentIdentity(ecosystem="composer", name="company/private", version="1.0.0"))
    client = advisory_client(transport=httpx.MockTransport(handler), namespace_policy=policy)
    assert client.query_osv_batch([component]).status == "success"
    assert requests == [{"queries": [{"package": {"ecosystem": "Packagist", "name": "symfony/http-foundation"}, "version": "7.1.3"}]}]


@pytest.mark.parametrize("value", ("https://packagist.org/symfony/http-foundation", "symfony/*", "Symfony/HTTP", "../private/package", "symfony/http-foundation,"))
def test_public_composer_attestation_rejects_urls_wildcards_case_paths_and_empty_entries(monkeypatch, tmp_path, value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_COMPOSER_PACKAGES", value)
    with pytest.raises(ValueError, match="INSPECTRA_PUBLIC_ADVISORY_PUBLIC_COMPOSER_PACKAGES"):
        load_settings()


def test_maven_attestation_is_exact_and_osv_payload_contains_only_coordinate_and_version(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES", "org.apache.commons:commons-lang3")
    settings = load_settings()
    policy = PublicAdvisoryEgressClient.from_settings(settings).namespace_policy
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    component = PublicComponentIdentity(ecosystem="maven", name="org.apache.commons:commons-lang3", version="3.14.0")
    assert policy.allows_attested_public_maven(component)
    client = advisory_client(transport=httpx.MockTransport(handler), namespace_policy=policy)
    assert client.query_osv_batch([component]).status == "success"
    assert requests == [{"queries": [{"package": {"ecosystem": "Maven", "name": "org.apache.commons:commons-lang3"}, "version": "3.14.0"}]}]


@pytest.mark.parametrize("value", ("https://repo1.maven.org/x:y", "org.example:*", "Org.Example:artifact", "../org.example:artifact", "org.example:artifact,"))
def test_public_maven_attestation_rejects_locators_wildcards_case_paths_and_empty_entries(monkeypatch, tmp_path, value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES", value)
    with pytest.raises(ValueError, match="INSPECTRA_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES"):
        load_settings()


def test_nuget_attestation_normalizes_case_and_osv_payload_contains_only_name_and_version(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES", "Newtonsoft.Json")
    settings = load_settings()
    policy = PublicAdvisoryEgressClient.from_settings(settings).namespace_policy
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    component = PublicComponentIdentity(
        ecosystem="nuget", name="newtonsoft.json", version="013.0.03.0-BETA.010+private-build"
    )
    assert settings.public_advisory_public_nuget_packages == ("newtonsoft.json",)
    assert policy.allows_attested_public_nuget(component)
    client = advisory_client(transport=httpx.MockTransport(handler), namespace_policy=policy)
    assert client.query_osv_batch([component]).status == "success"
    assert requests == [{"queries": [{"package": {"ecosystem": "NuGet", "name": "newtonsoft.json"}, "version": "13.0.3-beta.10"}]}]
    assert "private-build" not in json.dumps(requests)


@pytest.mark.parametrize("value", ("https://api.nuget.org/x", "company.*", "../package", "package,", ""))
def test_public_nuget_attestation_rejects_locators_wildcards_paths_and_empty_entries(monkeypatch, tmp_path, value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES", value)
    if not value:
        assert load_settings().public_advisory_public_nuget_packages == ()
    else:
        with pytest.raises(ValueError, match="INSPECTRA_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES"):
            load_settings()


@pytest.mark.parametrize(
    "value",
    ("https://golang.org/x/text", "golang.org/x/*", "github.com/User/Repo", "../private/module", "golang.org/x/text,"),
)
def test_public_go_attestation_rejects_urls_wildcards_case_paths_and_empty_entries(monkeypatch, tmp_path, value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_GO_MODULES", value)
    with pytest.raises(ValueError, match="INSPECTRA_PUBLIC_ADVISORY_PUBLIC_GO_MODULES"):
        load_settings()


@pytest.mark.parametrize("value", ("requests,*", "https://pypi.org/simple/requests", "../requests", "requests,"))
def test_public_pypi_attestation_rejects_locators_wildcards_and_empty_entries(monkeypatch, tmp_path, value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES", value)

    with pytest.raises(ValueError, match="INSPECTRA_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES"):
        load_settings()


def test_osv_rejects_pypi_without_operator_attestation_and_sends_only_attested_minimal_identity():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    pypi_component = PublicComponentIdentity(ecosystem="pypi", name="Requests_Auth", version="2.32.3")
    unapproved = advisory_client(transport=httpx.MockTransport(handler))
    assert unapproved.query_osv_batch([pypi_component]).status == "invalid_request"
    assert requests == []

    approved = PublicAdvisoryEgressClient(
        enabled=True,
        timeout_seconds=1,
        max_response_bytes=1024,
        max_concurrency=1,
        max_retries=0,
        max_batch_components=2,
        namespace_policy=PublicAdvisoryNamespacePolicy(public_pypi_packages=("requests-auth",)),
        http_transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    )
    result = approved.query_osv_batch([pypi_component])

    assert result.status == "success"
    assert requests == [{"queries": [{"package": {"ecosystem": "PyPI", "name": "requests-auth"}, "version": "2.32.3"}]}]


def test_cache_uses_only_one_way_request_key_and_prevents_a_repeat_network_call(tmp_path):
    component = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")
    query = normalize_osv_component_identity(component)
    assert query is not None
    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, max_response_bytes=1024)
    key = public_advisory_cache_key("osv", [query])
    cache.put("osv", key, b'{"results":[{"vulns":[]}]}')

    def reject_network(_: httpx.Request) -> httpx.Response:
        raise AssertionError("Fresh cache must not use the network.")

    result = advisory_client(cache=cache, transport=httpx.MockTransport(reject_network)).query_osv_batch([component])

    assert result.status == "success"
    assert result.cache_status == "fresh"
    assert result.attempts == 0
    stored_document = next((tmp_path / "osv").glob("*.json")).read_text(encoding="utf-8")
    assert "react" not in stored_document
    assert "project" not in stored_document
    assert "owner" not in stored_document


def test_cache_results_expose_only_provider_freshness_timestamps_not_request_identity(tmp_path):
    component = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")
    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, max_response_bytes=1024)
    client = advisory_client(
        cache=cache,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"results": [{"vulns": []}]})),
    )

    first = client.query_osv_batch([component])
    second = client.query_osv_batch([component])

    assert first.cache_status == "miss"
    assert first.fetched_at is not None and first.expires_at is not None
    assert second.cache_status == "fresh"
    assert (second.fetched_at, second.expires_at) == (first.fetched_at, first.expires_at)


def test_stale_cache_is_explicitly_degraded_when_provider_is_unavailable(tmp_path):
    component = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")
    query = normalize_osv_component_identity(component)
    assert query is not None
    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=1, max_response_bytes=1024)
    cache.put(
        "osv",
        public_advisory_cache_key("osv", [query]),
        b'{"results":[{"vulns":[]}]}',
        now=datetime.now(timezone.utc) - timedelta(minutes=2),
    )

    client = advisory_client(
        cache=cache,
        max_retries=0,
        transport=httpx.MockTransport(lambda _: httpx.Response(503)),
    )
    result = client.query_osv_batch([component])

    assert result.status == "stale_cached"
    assert result.cache_status == "stale"
    assert result.body == b'{"results":[{"vulns":[]}]}'


def test_cache_retention_uses_an_injected_clock_and_discards_data_after_its_bound(tmp_path):
    component = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")
    query = normalize_osv_component_identity(component)
    assert query is not None
    observed_at = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
    cache = PublicAdvisoryResponseCache(
        tmp_path,
        ttl_seconds=60,
        retention_seconds=120,
        max_response_bytes=1024,
        clock=lambda: observed_at,
    )
    key = public_advisory_cache_key("osv", [query])
    cache.put("osv", key, b'{"results":[{"vulns":[]}]}')

    stale = cache.get("osv", key, now=observed_at + timedelta(seconds=61))
    expired = cache.get("osv", key, now=observed_at + timedelta(seconds=121))

    assert stale is not None
    assert stale.is_fresh_at(observed_at + timedelta(seconds=61)) is False
    assert expired is None
    assert not (tmp_path / "osv" / f"{key}.json").exists()


def test_retention_expiry_prevents_stale_fallback_and_reuses_no_project_data(tmp_path):
    component = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")
    query = normalize_osv_component_identity(component)
    assert query is not None
    observed_at = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
    cache = PublicAdvisoryResponseCache(tmp_path, ttl_seconds=60, retention_seconds=120, max_response_bytes=1024)
    cache.put("osv", public_advisory_cache_key("osv", [query]), b'{"results":[{"vulns":[]}]}', now=observed_at)

    client = PublicAdvisoryEgressClient(
        enabled=True,
        timeout_seconds=1,
        max_response_bytes=1024,
        max_concurrency=1,
        max_retries=0,
        max_batch_components=2,
        http_transport=httpx.MockTransport(lambda _: httpx.Response(503)),
        cache=cache,
        sleep=lambda _: None,
        clock=lambda: observed_at + timedelta(seconds=121),
    )
    result = client.query_osv_batch([component])

    assert result.status == "unavailable"
    assert result.cache_status == "miss"
    assert result.body is None


def test_provider_circuit_stops_cascading_requests_and_recovers_after_cooldown():
    observed_at = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
    clock = [observed_at]
    calls = 0
    available = False

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"results": [{}]}) if available else httpx.Response(503)

    client = PublicAdvisoryEgressClient(
        enabled=True,
        timeout_seconds=1,
        max_response_bytes=1024,
        max_concurrency=1,
        max_retries=0,
        max_batch_components=2,
        http_transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
        clock=lambda: clock[0],
    )
    component = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")

    assert [client.query_osv_batch([component]).status for _ in range(3)] == ["unavailable"] * 3
    blocked = client.query_osv_batch([component])
    assert blocked.status == "circuit_open"
    assert blocked.attempts == 0
    assert calls == 3

    available = True
    clock[0] = observed_at + timedelta(seconds=31)
    recovered = client.query_osv_batch([component])
    assert recovered.status == "success"
    assert calls == 4


def test_cisa_kev_cache_survives_client_restart_as_explicit_stale_fallback(tmp_path):
    observed_at = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
    catalog = json.loads(
        (Path(__file__).parent / "fixtures" / "cisa" / "kev-valid.json").read_text(encoding="utf-8")
    )
    first_cache = PublicAdvisoryResponseCache(
        tmp_path,
        ttl_seconds=60,
        retention_seconds=120,
        max_response_bytes=1024 * 1024,
        clock=lambda: observed_at,
    )
    first = PublicAdvisoryEgressClient(
        enabled=True,
        timeout_seconds=1,
        max_response_bytes=1024 * 1024,
        max_concurrency=1,
        max_retries=0,
        max_batch_components=2,
        http_transport=httpx.MockTransport(lambda _: httpx.Response(200, json=catalog)),
        cache=first_cache,
        sleep=lambda _: None,
        clock=lambda: observed_at,
    ).fetch_cisa_kev_feed()
    assert first.status == "success"

    calls = 0

    def unavailable(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    restarted_at = observed_at + timedelta(seconds=61)
    restarted_cache = PublicAdvisoryResponseCache(
        tmp_path,
        ttl_seconds=60,
        retention_seconds=120,
        max_response_bytes=1024 * 1024,
        clock=lambda: restarted_at,
    )
    restarted = PublicAdvisoryEgressClient(
        enabled=True,
        timeout_seconds=1,
        max_response_bytes=1024 * 1024,
        max_concurrency=1,
        max_retries=0,
        max_batch_components=2,
        http_transport=httpx.MockTransport(unavailable),
        cache=restarted_cache,
        sleep=lambda _: None,
        clock=lambda: restarted_at,
    ).fetch_cisa_kev_feed()

    assert calls == 1
    assert restarted.status == "stale_cached"
    assert restarted.cache_status == "stale"
    assert restarted.body == first.body
