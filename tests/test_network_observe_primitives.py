"""Tests for the ``network-observe`` capability driver primitives."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from torbrowser_driver import PathPolicy, TorBrowserDriver


@pytest.fixture()
def canned() -> list[dict]:
    return [
        {
            "url": "https://x.test/",
            "initiator_type": "navigation",
            "request_start": 0.0,
            "response_start": 10.0,
            "response_end": 20.0,
            "transfer_size": 100,
            "duration": 20.0,
            "decoded_body_size": 200,
            "next_hop_protocol": "h2",
        },
        {
            "url": "https://x.test/a.js",
            "initiator_type": "script",
            "request_start": 5.0,
            "response_start": 15.0,
            "response_end": 25.0,
            "transfer_size": 50,
            "duration": 20.0,
            "decoded_body_size": 100,
            "next_hop_protocol": "h2",
        },
        {
            "url": "https://other.test/img.png",
            "initiator_type": "img",
            "request_start": 6.0,
            "response_start": 16.0,
            "response_end": 26.0,
            "transfer_size": 30,
            "duration": 20.0,
            "decoded_body_size": 60,
            "next_hop_protocol": "h2",
        },
    ]


@pytest.fixture()
def drv(drv: TorBrowserDriver, canned: list[dict]) -> TorBrowserDriver:
    drv.webdriver.execute_script.return_value = canned
    return drv


def test_network_requests_returns_all(drv: TorBrowserDriver) -> None:
    result = drv.browser_network_requests()
    assert result["count"] == 3
    assert "performance API only" in result["note"]


def test_network_requests_filter(drv: TorBrowserDriver) -> None:
    result = drv.browser_network_requests(url_filter="other.test")
    assert result["count"] == 1
    assert result["requests"][0]["url"] == "https://other.test/img.png"


def test_network_requests_writes_file(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    result = drv.browser_network_requests(filename="net.json")
    written = Path(result["path"])
    assert written == (policy.output_dir / "net.json").resolve()
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["count"] == 3


def test_network_request_by_index(drv: TorBrowserDriver) -> None:
    result = drv.browser_network_request(1)
    assert result["url"] == "https://x.test/a.js"


def test_network_request_part_headers(drv: TorBrowserDriver) -> None:
    result = drv.browser_network_request(0, part="headers")
    assert result["available"] is False
    assert result["entry"]["url"] == "https://x.test/"


def test_network_request_invalid_part(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError):
        drv.browser_network_request(0, part="bogus")


def test_network_request_out_of_range(drv: TorBrowserDriver) -> None:
    with pytest.raises(IndexError):
        drv.browser_network_request(99)
