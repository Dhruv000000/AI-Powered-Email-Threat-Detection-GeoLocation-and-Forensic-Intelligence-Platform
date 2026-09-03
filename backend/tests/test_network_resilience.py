"""
Automated Network Resilience & Timeout Regression Tests.
Verifies that all network operations (HTTP, DNS, WHOIS, GeoIP, and LLM generation)
strictly adhere to timeout limits, never hang the process, handle non-routable IPs gracefully,
and return valid fallback structures without uncaught exceptions.
"""
import time
import socket
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.network import (
    safe_http_get,
    safe_http_post,
    safe_dns_resolve,
    safe_whois_lookup,
    safe_llm_generate,
    DEFAULT_TIMEOUT_SEC,
)
from app.services.geo.geo_resolver import geo_resolver


@pytest.fixture
def client():
    return TestClient(app)


def test_global_socket_default_timeout():
    """Verify that global default socket timeout is configured to <= 3.0 seconds."""
    timeout = socket.getdefaulttimeout()
    assert timeout is not None, "Global socket default timeout must be set"
    assert timeout <= 3.0, f"Global socket timeout must be <= 3.0s, got {timeout}"


def test_safe_http_get_non_routable_ip_timeout():
    """
    Assert that HTTP GET to a non-routable blackhole IP (RFC 5737 TEST-NET-1: 192.0.2.1):
    1. Completes in under 4.0 seconds.
    2. Does not raise an uncaught exception.
    3. Returns a safe fallback structure.
    """
    start = time.monotonic()
    result = safe_http_get("http://192.0.2.1:81/test-blackhole", timeout=1.5)
    elapsed = time.monotonic() - start

    assert elapsed < 4.0, f"safe_http_get hung for {elapsed:.2f}s (must complete in < 4.0s)"
    assert isinstance(result, dict), "Result must be a dictionary fallback"
    assert result.get("status") in ("timeout", "failed", "error")
    assert "url" in result or "message" in result


def test_safe_http_post_non_routable_ip_timeout():
    """Verify safe_http_post timeout behavior on unreachable hosts."""
    start = time.monotonic()
    result = safe_http_post("http://192.0.2.1:81/api/endpoint", json={"test": 1}, timeout=1.5)
    elapsed = time.monotonic() - start

    assert elapsed < 4.0, f"safe_http_post hung for {elapsed:.2f}s"
    assert isinstance(result, dict)
    assert result.get("status") in ("timeout", "failed", "error")


def test_safe_dns_resolution_non_existent_domain():
    """
    Assert that DNS resolution of an invalid or non-existent domain:
    1. Completes in under 4.0 seconds.
    2. Does not raise an uncaught exception.
    3. Returns a safe empty list.
    """
    start = time.monotonic()
    records = safe_dns_resolve("non-existent-blackhole-192-0-2-1.invalid", timeout=1.5)
    elapsed = time.monotonic() - start

    assert elapsed < 4.0, f"DNS resolution took too long: {elapsed:.2f}s"
    assert isinstance(records, list), "DNS result must be a list"
    assert len(records) == 0, "Non-existent domain must yield empty list"


def test_safe_whois_lookup_non_routable_ip():
    """
    Assert that WHOIS lookup for a non-routable IP:
    1. Completes in under 4.0 seconds.
    2. Does not raise uncaught socket exceptions.
    3. Returns a structured fallback object.
    """
    start = time.monotonic()
    res = safe_whois_lookup("192.0.2.1", timeout=1.5)
    elapsed = time.monotonic() - start

    assert elapsed < 4.0, f"WHOIS lookup hung for {elapsed:.2f}s"
    assert isinstance(res, dict)
    assert "status" in res
    assert "registrar" in res


def test_geo_resolver_non_routable_blackhole_ip():
    """
    Assert that IP geolocation on non-routable / test networks (192.0.2.1):
    1. Completes immediately (< 1.0s).
    2. Does not raise any network errors.
    3. Correctly identifies it as bogon or returns valid coordinate structure.
    """
    start = time.monotonic()
    geo = geo_resolver.resolve_ip("192.0.2.1")
    elapsed = time.monotonic() - start

    assert elapsed < 1.0, f"Geo resolution took {elapsed:.2f}s"
    assert geo is not None
    assert geo.ip == "192.0.2.1"
    assert geo.is_bogon is True
    assert geo.country_name is not None


def test_safe_llm_generator_timeout_fallback():
    """
    Assert that an LLM call that hangs exceeds timeout and falls back to rule-based template:
    1. Completes within the timeout tolerance (< 4.0s).
    2. Never raises unhandled timeout exceptions.
    3. Returns fallback text.
    """
    def hanging_llm(prompt: str) -> str:
        time.sleep(10)  # Simulate hanging provider
        return "Simulated LLM"

    start = time.monotonic()
    result = safe_llm_generate("Analyze threat", timeout=1.0, llm_callable=hanging_llm)
    elapsed = time.monotonic() - start

    assert elapsed < 3.0, f"LLM generation hung for {elapsed:.2f}s"
    assert isinstance(result, str)
    assert len(result) > 0


def test_analyze_raw_endpoint_with_blackhole_indicators(client):
    """
    Assert that analyzing an email containing non-routable blackhole IPs (192.0.2.1):
    1. Completes cleanly without hanging or crashing.
    2. Does not throw 502 Bad Gateway or 500 error.
    3. Returns HTTP 200 with full analysis response.
    """
    raw_content = (
        "From: security@paypal-verify-alert.com\n"
        "To: victim@company.com\n"
        "Subject: Urgent: Verify Account Security\n"
        "Received: from mail.attacker.net (192.0.2.1) by mx.company.com; Thu, 03 Sep 2026 12:00:00 +0000\n"
        "\n"
        "Please visit http://192.0.2.1/login to secure your account immediately.\n"
    )

    start = time.monotonic()
    response = client.post(
        "/api/v1/email-analysis/analyze-raw",
        json={"raw_content": raw_content, "filename": "blackhole_test.eml", "force_reanalysis": True}
    )
    elapsed = time.monotonic() - start

    assert elapsed < 10.0, f"Endpoint took too long: {elapsed:.2f}s"
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    data = response.json()
    assert "analysis_id" in data
    assert "classification" in data
    assert data["classification"]["risk_score"] > 0
