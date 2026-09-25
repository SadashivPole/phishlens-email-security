from __future__ import annotations

import base64
from urllib.parse import unquote, urlsplit

from phishlens.config import VirusTotalConfig
from phishlens.enrichment.virustotal import VirusTotalProvider
from phishlens.models.ioc import IOC


def provider(requests):
    return VirusTotalProvider(
        VirusTotalConfig(api_key="test-key"),
        http_get=lambda request, timeout: (
            requests.append(request),
            (404, b"{}"),
        )[1],
    )


def requested_url_value(request) -> str:
    encoded = unquote(urlsplit(request.full_url).path.rsplit("/", 1)[-1])
    return base64.urlsafe_b64decode(
        encoded + "=" * (-len(encoded) % 4)
    ).decode("utf-8")


def test_virustotal_strips_userinfo_credentials_before_http():
    requests = []
    adapter = provider(requests)

    target = (
        "https://alice:CANARYPASS@example.test/"
        "reset?token=CANARYTOKEN&keep=1"
    )

    result = adapter.lookup_url(
        IOC("url", target, target, "test")
    )

    assert result.status == "no_match"
    assert len(requests) == 1

    provider_value = requested_url_value(requests[0])

    assert provider_value == "https://example.test/reset?keep=1"
    assert "alice" not in provider_value
    assert "CANARYPASS" not in provider_value
    assert "CANARYTOKEN" not in provider_value
    assert "CANARYPASS" not in requests[0].full_url


def test_virustotal_preserves_ipv6_host_and_port_without_userinfo():
    requests = []
    adapter = provider(requests)

    target = (
        "https://alice:CANARYPASS@[2001:db8::10]:8443/"
        "login?keep=1"
    )

    result = adapter.lookup_url(
        IOC("url", target, target, "test")
    )

    assert result.status == "no_match"
    assert len(requests) == 1

    provider_value = requested_url_value(requests[0])

    assert provider_value == "https://[2001:db8::10]:8443/login?keep=1"
    assert "alice" not in provider_value
    assert "CANARYPASS" not in provider_value
