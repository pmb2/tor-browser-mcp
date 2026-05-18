"""Unit tests for the helper-extension active primitives.

Covers the driver-side route table, the mock data-URL builder, the
``browser_route`` / ``browser_unroute`` / ``browser_route_list``
surface, and ``browser_network_state_set``. Everything runs against a
fake bridge that records outgoing requests; no Firefox is launched.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from torbrowser_driver._helper_extension_primitives import (
    _build_mock_data_url,
    _HelperExtensionCapabilityMixin,
    _resolve_route_mode,
)
from torbrowser_driver.exceptions import HelperUnavailable


class _FakeBridge:
    def __init__(self, connected: bool = True) -> None:
        self.connected = connected
        self.host = "127.0.0.1"
        self.port = 9999
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0):
        self.calls.append((method, dict(params or {})))
        return {"ok": True}

    def subscribe(self, name: str, sink) -> None:  # pragma: no cover - unused here
        return None


class _Driver(_HelperExtensionCapabilityMixin):
    def __init__(self, bridge: _FakeBridge | None) -> None:
        self._helper_bridge = bridge
        self._helper_addon_id = "helper@tor-browser-mcp.local"


# --- mock data-URL builder --------------------------------------------------


def test_build_mock_data_url_round_trip() -> None:
    url = _build_mock_data_url(200, "text/plain", "hello world", None)
    prefix, _, payload = url.partition(",")
    assert prefix == "data:text/plain;base64"
    assert base64.b64decode(payload).decode("utf-8") == "hello world"


def test_build_mock_data_url_carries_content_type() -> None:
    url = _build_mock_data_url(404, "application/json", '{"a":1}', {"X-Foo": "bar"})
    assert url.startswith("data:application/json;base64,")
    payload = url.split(",", 1)[1]
    assert base64.b64decode(payload).decode("utf-8") == '{"a":1}'


def test_build_mock_data_url_unicode_body() -> None:
    text = "snowman: \u2603"
    url = _build_mock_data_url(200, "text/plain", text, None)
    payload = url.split(",", 1)[1]
    assert base64.b64decode(payload).decode("utf-8") == text


# --- mode resolution --------------------------------------------------------


def test_resolve_route_mode_mock() -> None:
    assert _resolve_route_mode("body", None, None, None, None, None) == "mock"


def test_resolve_route_mode_redirect() -> None:
    assert (
        _resolve_route_mode(None, "https://x/", None, None, None, None) == "redirect"
    )


def test_resolve_route_mode_headers_request_set() -> None:
    assert (
        _resolve_route_mode(None, None, {"X-A": "1"}, None, None, None) == "headers"
    )


def test_resolve_route_mode_headers_request_remove() -> None:
    assert _resolve_route_mode(None, None, None, ["X-A"], None, None) == "headers"


def test_resolve_route_mode_headers_response_set() -> None:
    assert (
        _resolve_route_mode(None, None, None, None, {"X-A": "1"}, None) == "headers"
    )


def test_resolve_route_mode_headers_response_remove() -> None:
    assert _resolve_route_mode(None, None, None, None, None, ["X-A"]) == "headers"


def test_resolve_route_mode_empty_raises() -> None:
    with pytest.raises(ValueError, match="one of"):
        _resolve_route_mode(None, None, None, None, None, None)


def test_resolve_route_mode_mock_plus_redirect_raises() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        _resolve_route_mode("b", "https://x/", None, None, None, None)


def test_resolve_route_mode_mock_plus_headers_raises() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        _resolve_route_mode("b", None, {"X": "1"}, None, None, None)


def test_resolve_route_mode_redirect_plus_headers_raises() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        _resolve_route_mode(None, "https://x/", None, None, None, ["Y"])


# --- browser_route validation -----------------------------------------------


def test_route_rejects_invalid_match_pattern() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="match pattern"):
        drv.browser_route("not-a-pattern", body="x")


def test_route_raises_when_bridge_missing() -> None:
    drv = _Driver(bridge=None)
    with pytest.raises(HelperUnavailable):
        drv.browser_route("*://example.com/*", body="x")


def test_route_mode_mutual_exclusion_mock_redirect() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="mutually exclusive"):
        drv.browser_route("*://e/*", body="x", redirect_url="https://e/")


def test_route_mode_mutual_exclusion_mock_headers() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="mutually exclusive"):
        drv.browser_route("*://e/*", body="x", set_request_headers={"X": "1"})


def test_route_mode_mutual_exclusion_redirect_headers() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="mutually exclusive"):
        drv.browser_route(
            "*://e/*",
            redirect_url="https://e/",
            remove_response_headers=["X"],
        )


def test_route_requires_a_mode() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="one of"):
        drv.browser_route("*://e/*")


# --- browser_route add/list/remove round-trip -------------------------------


def test_route_add_mock_calls_bridge_with_data_url_payload() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    result = drv.browser_route(
        "*://example.com/*",
        status=200,
        body="ok",
        content_type="text/plain",
    )
    assert "route_id" in result
    method, params = bridge.calls[-1]
    assert method == "route.add"
    assert params["mode"] == "mock"
    assert params["pattern"] == "*://example.com/*"
    assert params["redirect_url"].startswith("data:text/plain;base64,")
    assert base64.b64decode(params["redirect_url"].split(",", 1)[1]).decode("utf-8") == "ok"


def test_route_add_redirect_passes_url_through() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv.browser_route("*://example.com/*", redirect_url="https://other/")
    _, params = bridge.calls[-1]
    assert params["mode"] == "redirect"
    assert params["redirect_url"] == "https://other/"


def test_route_add_headers_passes_edit_lists() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv.browser_route(
        "*://example.com/*",
        set_request_headers={"X-Req": "1"},
        remove_request_headers=["X-Drop"],
        set_response_headers={"X-Resp": "2"},
        remove_response_headers=["X-Strip"],
    )
    _, params = bridge.calls[-1]
    assert params["mode"] == "headers"
    assert params["set_request_headers"] == {"X-Req": "1"}
    assert params["remove_request_headers"] == ["X-Drop"]
    assert params["set_response_headers"] == {"X-Resp": "2"}
    assert params["remove_response_headers"] == ["X-Strip"]


def test_route_list_echoes_mode_specific_fields() -> None:
    drv = _Driver(bridge=_FakeBridge())
    drv.browser_route("*://m/*", body="hello", content_type="text/plain")
    drv.browser_route("*://r/*", redirect_url="https://r2/")
    drv.browser_route("*://h/*", set_request_headers={"X": "1"})

    routes = drv.browser_route_list()
    assert len(routes) == 3
    by_pattern = {r["pattern"]: r for r in routes}

    mock_entry = by_pattern["*://m/*"]
    assert mock_entry["mode"] == "mock"
    assert mock_entry["status"] == 200
    assert mock_entry["content_type"] == "text/plain"
    assert mock_entry["body_size"] == len("hello".encode("utf-8"))
    assert mock_entry["redirect_url"] is None

    redirect_entry = by_pattern["*://r/*"]
    assert redirect_entry["mode"] == "redirect"
    assert redirect_entry["redirect_url"] == "https://r2/"
    assert redirect_entry["body_size"] is None
    assert redirect_entry["status"] is None

    headers_entry = by_pattern["*://h/*"]
    assert headers_entry["mode"] == "headers"
    assert headers_entry["set_request_headers"] == {"X": "1"}
    assert headers_entry["remove_request_headers"] is None


def test_route_list_orders_by_priority_then_insertion() -> None:
    drv = _Driver(bridge=_FakeBridge())
    r_low = drv.browser_route("*://a/*", body="a", priority=1)["route_id"]
    r_high1 = drv.browser_route("*://b/*", body="b", priority=10)["route_id"]
    r_default = drv.browser_route("*://c/*", body="c")["route_id"]
    r_high2 = drv.browser_route("*://d/*", body="d", priority=10)["route_id"]

    ids = [r["route_id"] for r in drv.browser_route_list()]
    # priority 10 first (high1 then high2 by insertion), then priority 1,
    # then default priority 0.
    assert ids == [r_high1, r_high2, r_low, r_default]


def test_unroute_by_route_id_returns_one() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    rid = drv.browser_route("*://example.com/*", body="x")["route_id"]
    bridge.calls.clear()

    result = drv.browser_unroute(route_id=rid)
    assert result == {"removed": 1}
    assert drv.browser_route_list() == []
    method, params = bridge.calls[-1]
    assert method == "route.remove"
    assert params["route_ids"] == [rid]


def test_unroute_by_route_id_unknown_returns_zero() -> None:
    drv = _Driver(bridge=_FakeBridge())
    assert drv.browser_unroute(route_id="missing") == {"removed": 0}


def test_unroute_by_pattern_removes_all_matching() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv.browser_route("*://example.com/*", body="a")
    drv.browser_route("*://example.com/*", body="b", priority=5)
    drv.browser_route("*://other.com/*", body="c")
    bridge.calls.clear()

    result = drv.browser_unroute(pattern="*://example.com/*")
    assert result == {"removed": 2}
    remaining = drv.browser_route_list()
    assert len(remaining) == 1
    assert remaining[0]["pattern"] == "*://other.com/*"
    method, params = bridge.calls[-1]
    assert method == "route.remove"
    assert len(params["route_ids"]) == 2


def test_unroute_by_pattern_no_match_returns_zero_and_no_call() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv.browser_route("*://example.com/*", body="a")
    bridge.calls.clear()
    assert drv.browser_unroute(pattern="*://nope/*") == {"removed": 0}
    assert bridge.calls == []


def test_unroute_requires_exactly_one_argument() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="exactly one"):
        drv.browser_unroute()
    with pytest.raises(ValueError, match="exactly one"):
        drv.browser_unroute(route_id="a", pattern="*://x/*")


def test_unroute_raises_when_bridge_missing() -> None:
    drv = _Driver(bridge=None)
    with pytest.raises(HelperUnavailable):
        drv.browser_unroute(route_id="r")


def test_route_list_empty_when_no_routes() -> None:
    drv = _Driver(bridge=_FakeBridge())
    assert drv.browser_route_list() == []


# --- browser_network_state_set ----------------------------------------------


def test_network_state_set_online() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    result = drv.browser_network_state_set("online")
    assert result == {"state": "online"}
    method, params = bridge.calls[-1]
    assert method == "network_state.set"
    assert params == {"state": "online"}


def test_network_state_set_offline() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    result = drv.browser_network_state_set("offline")
    assert result == {"state": "offline"}
    _, params = bridge.calls[-1]
    assert params == {"state": "offline"}


def test_network_state_set_round_trip_toggle() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv.browser_network_state_set("offline")
    drv.browser_network_state_set("online")
    calls = [c[1]["state"] for c in bridge.calls if c[0] == "network_state.set"]
    assert calls == ["offline", "online"]


@pytest.mark.parametrize("bad", ["OFFLINE", "Online", "disabled", "", None, 1])
def test_network_state_set_rejects_invalid_state(bad: Any) -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError):
        drv.browser_network_state_set(bad)  # type: ignore[arg-type]


def test_network_state_set_raises_when_bridge_missing() -> None:
    drv = _Driver(bridge=None)
    with pytest.raises(HelperUnavailable):
        drv.browser_network_state_set("offline")
