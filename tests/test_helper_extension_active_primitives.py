"""Unit tests for the helper-extension active primitives.

Covers the driver-side route table, mock fulfillment on the
proxy-intercept substrate, the ``browser_route`` / ``browser_unroute`` /
``browser_route_list`` surface, and ``browser_network_state_set``.
Everything runs against a fake bridge that records outgoing requests
and a fake proxy manager that records mock-route registrations; no
Firefox is launched.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from torbrowser_driver import PathPolicy
from torbrowser_driver._helper_extension_primitives import (
    _HelperExtensionCapabilityMixin,
    _resolve_route_mode,
)
from torbrowser_driver.exceptions import HelperUnavailable, ProxyInterceptError


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


class _FakeProxyManager:
    def __init__(self, alive: bool = True) -> None:
        self._alive = alive
        self.mocks: dict[str, dict[str, Any]] = {}
        self.mock_log: list[tuple[str, str, dict[str, Any]]] = []

    def is_alive(self) -> bool:
        return self._alive

    def register_mock_route(
        self,
        *,
        route_id: str,
        pattern: str,
        status: int,
        body: bytes,
        content_type: str | None,
        headers: dict[str, str] | None,
        priority: int,
        insertion_index: int,
    ) -> None:
        entry = {
            "pattern": pattern,
            "status": int(status),
            "body": bytes(body),
            "content_type": content_type,
            "headers": dict(headers or {}),
            "priority": int(priority),
            "insertion_index": int(insertion_index),
        }
        self.mocks[route_id] = entry
        self.mock_log.append(("register", route_id, entry))

    def unregister_mock_route(self, route_id: str) -> bool:
        existed = self.mocks.pop(route_id, None) is not None
        self.mock_log.append(("unregister", route_id, {}))
        return existed


class _Driver(_HelperExtensionCapabilityMixin):
    def __init__(
        self,
        bridge: _FakeBridge | None,
        proxy_manager: _FakeProxyManager | None = None,
    ) -> None:
        self._helper_bridge = bridge
        self._helper_addon_id = "helper@tor-browser-mcp.local"
        self._proxy_manager = proxy_manager


def _drv_with_mock_support(
    bridge: _FakeBridge | None = None,
    proxy: _FakeProxyManager | None = None,
) -> _Driver:
    """Construct a driver wired up with a proxy manager for mock-mode."""

    return _Driver(
        bridge=bridge if bridge is not None else _FakeBridge(),
        proxy_manager=proxy if proxy is not None else _FakeProxyManager(),
    )


_ROUTE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


# --- _proxy_manager_for_mock_or_raise ---------------------------------------


def test_proxy_manager_for_mock_or_raise_returns_live_manager() -> None:
    proxy = _FakeProxyManager()
    drv = _drv_with_mock_support(proxy=proxy)
    assert drv._proxy_manager_for_mock_or_raise() is proxy


def test_proxy_manager_for_mock_or_raise_when_absent() -> None:
    drv = _Driver(bridge=_FakeBridge(), proxy_manager=None)
    with pytest.raises(ProxyInterceptError, match="proxy-intercept"):
        drv._proxy_manager_for_mock_or_raise()


def test_proxy_manager_for_mock_or_raise_when_dead() -> None:
    drv = _drv_with_mock_support(proxy=_FakeProxyManager(alive=False))
    with pytest.raises(ProxyInterceptError, match="proxy-intercept"):
        drv._proxy_manager_for_mock_or_raise()


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
    drv = _drv_with_mock_support()
    with pytest.raises(ValueError, match="match pattern"):
        drv.browser_route("not-a-pattern", body="x")


def test_route_raises_when_bridge_missing() -> None:
    drv = _Driver(bridge=None, proxy_manager=_FakeProxyManager())
    with pytest.raises(HelperUnavailable):
        drv.browser_route("*://example.com/*", body="x")


def test_route_mock_raises_when_proxy_intercept_disabled() -> None:
    drv = _Driver(bridge=_FakeBridge(), proxy_manager=None)
    with pytest.raises(ProxyInterceptError, match="proxy-intercept"):
        drv.browser_route("*://example.com/*", body="x")


def test_route_mode_mutual_exclusion_mock_redirect() -> None:
    drv = _drv_with_mock_support()
    with pytest.raises(ValueError, match="mutually exclusive"):
        drv.browser_route("*://e/*", body="x", redirect_url="https://e/")


def test_route_mode_mutual_exclusion_mock_headers() -> None:
    drv = _drv_with_mock_support()
    with pytest.raises(ValueError, match="mutually exclusive"):
        drv.browser_route("*://e/*", body="x", set_request_headers={"X": "1"})


def test_route_mode_mutual_exclusion_redirect_headers() -> None:
    drv = _drv_with_mock_support()
    with pytest.raises(ValueError, match="mutually exclusive"):
        drv.browser_route(
            "*://e/*",
            redirect_url="https://e/",
            remove_response_headers=["X"],
        )


def test_route_redirect_url_rejects_non_http_scheme() -> None:
    drv = _drv_with_mock_support()
    with pytest.raises(ValueError, match="absolute http"):
        drv.browser_route("*://e/*", redirect_url="file:///etc/passwd")


def test_route_requires_a_mode() -> None:
    drv = _drv_with_mock_support()
    with pytest.raises(ValueError, match="one of"):
        drv.browser_route("*://e/*")


# --- browser_route add/list/remove round-trip -------------------------------


def test_route_add_mock_registers_on_proxy_substrate_only() -> None:
    bridge = _FakeBridge()
    proxy = _FakeProxyManager()
    drv = _Driver(bridge=bridge, proxy_manager=proxy)
    result = drv.browser_route(
        "*://example.com/*",
        status=200,
        body="ok",
        content_type="text/plain",
    )
    route_id = result["route_id"]
    assert _ROUTE_ID_RE.match(route_id), route_id
    # The WebExtension must not see mock-mode routes at all.
    assert bridge.calls == []
    entry = proxy.mocks[route_id]
    assert entry["pattern"] == "*://example.com/*"
    assert entry["status"] == 200
    assert entry["body"] == b"ok"
    assert entry["content_type"] == "text/plain"


def test_route_add_redirect_passes_url_through() -> None:
    drv = _drv_with_mock_support()
    drv.browser_route("*://example.com/*", redirect_url="https://other/")
    bridge = drv._helper_bridge
    assert bridge is not None
    _, params = bridge.calls[-1]
    assert params["mode"] == "redirect"
    assert params["redirect_url"] == "https://other/"


def test_route_add_headers_passes_edit_lists() -> None:
    drv = _drv_with_mock_support()
    drv.browser_route(
        "*://example.com/*",
        set_request_headers={"X-Req": "1"},
        remove_request_headers=["X-Drop"],
        set_response_headers={"X-Resp": "2"},
        remove_response_headers=["X-Strip"],
    )
    bridge = drv._helper_bridge
    assert bridge is not None
    _, params = bridge.calls[-1]
    assert params["mode"] == "headers"
    assert params["set_request_headers"] == {"X-Req": "1"}
    assert params["remove_request_headers"] == ["X-Drop"]
    assert params["set_response_headers"] == {"X-Resp": "2"}
    assert params["remove_response_headers"] == ["X-Strip"]


def test_route_add_mock_headers_passed_to_proxy() -> None:
    proxy = _FakeProxyManager()
    drv = _drv_with_mock_support(proxy=proxy)
    result = drv.browser_route(
        "*://m/*",
        status=418,
        body="hello",
        content_type="text/plain",
        headers={"X-Test": "yes"},
    )
    entry = proxy.mocks[result["route_id"]]
    assert entry["status"] == 418
    assert entry["body"] == b"hello"
    assert entry["content_type"] == "text/plain"
    assert entry["headers"] == {"X-Test": "yes"}


def test_route_list_echoes_mode_specific_fields() -> None:
    drv = _drv_with_mock_support()
    drv.browser_route(
        "*://m/*",
        status=418,
        body="hello",
        content_type="text/plain",
        headers={"X-Test": "yes"},
    )
    drv.browser_route("*://r/*", redirect_url="https://r2/")
    drv.browser_route("*://h/*", set_request_headers={"X": "1"})

    result = drv.browser_route_list()
    assert set(result.keys()) == {"routes", "count", "total", "truncated"}
    routes = result["routes"]
    assert len(routes) == 3
    assert result["count"] == 3
    assert result["total"] == 3
    assert result["truncated"] is False
    by_pattern = {r["pattern"]: r for r in routes}

    mock_entry = by_pattern["*://m/*"]
    assert mock_entry["mode"] == "mock"
    assert mock_entry["status"] == 418
    assert mock_entry["content_type"] == "text/plain"
    assert mock_entry["body_size"] == len(b"hello")
    assert mock_entry["headers"] == {"X-Test": "yes"}
    # Mock entries are fulfilled inline on the proxy substrate and have
    # no redirect target to surface.
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
    drv = _drv_with_mock_support()
    r_low = drv.browser_route("*://a/*", body="a", priority=1)["route_id"]
    r_high1 = drv.browser_route("*://b/*", body="b", priority=10)["route_id"]
    r_default = drv.browser_route("*://c/*", body="c")["route_id"]
    r_high2 = drv.browser_route("*://d/*", body="d", priority=10)["route_id"]

    listed = drv.browser_route_list()
    ids = [r["route_id"] for r in listed["routes"]]
    # priority 10 first (high1 then high2 by insertion), then priority 1,
    # then default priority 0.
    assert ids == [r_high1, r_high2, r_low, r_default]


def test_unroute_by_route_id_returns_one_for_mock() -> None:
    bridge = _FakeBridge()
    proxy = _FakeProxyManager()
    drv = _Driver(bridge=bridge, proxy_manager=proxy)
    rid = drv.browser_route("*://example.com/*", body="x")["route_id"]
    assert rid in proxy.mocks
    bridge.calls.clear()
    proxy.mock_log.clear()

    result = drv.browser_unroute(route_id=rid)
    assert result == {"removed": 1}
    assert drv.browser_route_list() == {
        "routes": [],
        "count": 0,
        "total": 0,
        "truncated": False,
    }
    # Mock removal goes through the proxy substrate; the extension
    # never knew about this route and must not receive a remove call.
    assert bridge.calls == []
    assert rid not in proxy.mocks
    assert any(op == "unregister" and r == rid for op, r, _ in proxy.mock_log)


def test_unroute_by_route_id_returns_one_for_redirect() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge, proxy_manager=_FakeProxyManager())
    rid = drv.browser_route("*://example.com/*", redirect_url="https://e/")[
        "route_id"
    ]
    bridge.calls.clear()

    result = drv.browser_unroute(route_id=rid)
    assert result == {"removed": 1}
    method, params = bridge.calls[-1]
    assert method == "route.remove"
    assert params["route_ids"] == [rid]


def test_unroute_by_route_id_unknown_returns_zero() -> None:
    drv = _drv_with_mock_support()
    assert drv.browser_unroute(route_id="missing") == {"removed": 0}


def test_unroute_by_pattern_removes_all_matching() -> None:
    bridge = _FakeBridge()
    proxy = _FakeProxyManager()
    drv = _Driver(bridge=bridge, proxy_manager=proxy)
    rid_a = drv.browser_route("*://example.com/*", body="a")["route_id"]
    rid_b = drv.browser_route("*://example.com/*", body="b", priority=5)["route_id"]
    rid_c = drv.browser_route("*://other.com/*", body="c")["route_id"]
    bridge.calls.clear()
    proxy.mock_log.clear()

    result = drv.browser_unroute(pattern="*://example.com/*")
    assert result == {"removed": 2}
    remaining = drv.browser_route_list()["routes"]
    assert len(remaining) == 1
    assert remaining[0]["pattern"] == "*://other.com/*"
    # All three were mock-mode, so the bridge sees no remove calls.
    assert bridge.calls == []
    assert rid_a not in proxy.mocks
    assert rid_b not in proxy.mocks
    assert rid_c in proxy.mocks


def test_unroute_by_pattern_splits_modes_correctly() -> None:
    bridge = _FakeBridge()
    proxy = _FakeProxyManager()
    drv = _Driver(bridge=bridge, proxy_manager=proxy)
    rid_mock = drv.browser_route("*://example.com/*", body="a")["route_id"]
    rid_redirect = drv.browser_route(
        "*://example.com/*", redirect_url="https://r/"
    )["route_id"]
    bridge.calls.clear()
    proxy.mock_log.clear()

    result = drv.browser_unroute(pattern="*://example.com/*")
    assert result == {"removed": 2}
    # The redirect entry goes through the extension; the mock entry
    # is dropped from the proxy substrate directly.
    method, params = bridge.calls[-1]
    assert method == "route.remove"
    assert params["route_ids"] == [rid_redirect]
    assert rid_mock not in proxy.mocks


def test_unroute_by_pattern_no_match_returns_zero_and_no_call() -> None:
    drv = _drv_with_mock_support()
    drv.browser_route("*://example.com/*", body="a")
    bridge = drv._helper_bridge
    assert bridge is not None
    bridge.calls.clear()
    assert drv.browser_unroute(pattern="*://nope/*") == {"removed": 0}
    assert bridge.calls == []


def test_unroute_requires_exactly_one_argument() -> None:
    drv = _drv_with_mock_support()
    with pytest.raises(ValueError, match="exactly one"):
        drv.browser_unroute()
    with pytest.raises(ValueError, match="exactly one"):
        drv.browser_unroute(route_id="a", pattern="*://x/*")


def test_unroute_raises_when_bridge_missing() -> None:
    drv = _Driver(bridge=None, proxy_manager=_FakeProxyManager())
    with pytest.raises(HelperUnavailable):
        drv.browser_unroute(route_id="r")


def test_route_list_empty_when_no_routes() -> None:
    drv = _drv_with_mock_support()
    assert drv.browser_route_list() == {
        "routes": [],
        "count": 0,
        "total": 0,
        "truncated": False,
    }


def test_route_list_limit_and_file_output(tmp_path: Path) -> None:
    drv = _drv_with_mock_support()
    drv.config = SimpleNamespace(
        path_policy=PathPolicy.from_config(output_dir=tmp_path / "out")
    )
    drv.browser_route("*://a/*", body="a", priority=1)
    drv.browser_route("*://b/*", body="b", priority=2)

    limited = drv.browser_route_list(limit=1)
    assert len(limited["routes"]) == 1
    assert limited["count"] == 1
    assert limited["total"] == 2
    assert limited["truncated"] is True

    written = drv.browser_route_list(filename="routes.json")
    path = Path(written["path"])
    assert "routes" not in written
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert len(payload["routes"]) == 2


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
    with pytest.raises(ValueError, match=r"state must be 'online' or 'offline'"):
        drv.browser_network_state_set(bad)  # type: ignore[arg-type]


def test_network_state_set_raises_when_bridge_missing() -> None:
    drv = _Driver(bridge=None)
    with pytest.raises(HelperUnavailable):
        drv.browser_network_state_set("offline")
