"""Unit tests for the helper-extension active primitives.

Covers the driver-side route table, mock registration against the
bridge, the ``browser_route`` / ``browser_unroute`` /
``browser_route_list`` surface, and ``browser_network_state_set``.
Everything runs against a fake bridge that records outgoing requests
and mock registrations; no Firefox is launched.
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
from torbrowser_driver.exceptions import HelperUnavailable


class _FakeBridge:
    def __init__(self, connected: bool = True) -> None:
        self.connected = connected
        self.host = "127.0.0.1"
        self.port = 9999
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.mocks: dict[str, dict[str, Any]] = {}
        self.mock_log: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0):
        self.calls.append((method, dict(params or {})))
        return {"ok": True}

    def subscribe(self, name: str, sink) -> None:  # pragma: no cover - unused here
        return None

    def register_mock(
        self,
        route_id: str,
        status: int,
        headers: dict[str, str] | None,
        body: bytes,
    ) -> None:
        entry = {
            "status": int(status),
            "headers": dict(headers or {}),
            "body": bytes(body),
        }
        self.mocks[route_id] = entry
        self.mock_log.append(("register", route_id, entry))

    def unregister_mock(self, route_id: str) -> None:
        self.mocks.pop(route_id, None)
        self.mock_log.append(("unregister", route_id, {}))


class _Driver(_HelperExtensionCapabilityMixin):
    def __init__(self, bridge: _FakeBridge | None) -> None:
        self._helper_bridge = bridge
        self._helper_addon_id = "helper@tor-browser-mcp.local"


_ROUTE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


# --- _register_mock_on_bridge ------------------------------------------------


def test_register_mock_on_bridge_returns_bridge_url_and_records_entry() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    url = drv._register_mock_on_bridge(
        "abc123",
        200,
        "hello",
        "text/plain",
        None,
    )
    assert url == "http://127.0.0.1:9999/mock/abc123"
    assert bridge.mocks["abc123"] == {
        "status": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": b"hello",
    }


def test_register_mock_on_bridge_preserves_explicit_content_type() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv._register_mock_on_bridge(
        "abc",
        201,
        '{"a":1}',
        "text/plain",
        {"Content-Type": "application/json", "X-Foo": "bar"},
    )
    entry = bridge.mocks["abc"]
    # Explicit Content-Type wins over the content_type kwarg.
    assert entry["headers"]["Content-Type"] == "application/json"
    assert entry["headers"]["X-Foo"] == "bar"


def test_register_mock_on_bridge_encodes_string_body_as_utf8() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv._register_mock_on_bridge("r", 200, "snow \u2603", "text/plain", None)
    assert bridge.mocks["r"]["body"] == "snow \u2603".encode("utf-8")


def test_register_mock_on_bridge_accepts_bytes_body_verbatim() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    payload = bytes(range(256))
    drv._register_mock_on_bridge("r", 200, payload, None, None)
    assert bridge.mocks["r"]["body"] == payload


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


def test_route_redirect_url_rejects_non_http_scheme() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="absolute http"):
        drv.browser_route("*://e/*", redirect_url="file:///etc/passwd")


def test_route_requires_a_mode() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="one of"):
        drv.browser_route("*://e/*")


# --- browser_route add/list/remove round-trip -------------------------------


def test_route_add_mock_sends_redirect_mode_pointing_at_bridge() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    result = drv.browser_route(
        "*://example.com/*",
        status=200,
        body="ok",
        content_type="text/plain",
    )
    route_id = result["route_id"]
    assert _ROUTE_ID_RE.match(route_id), route_id
    method, params = bridge.calls[-1]
    assert method == "route.add"
    # The extension only ever sees redirect-mode; mock-mode is a
    # driver-side label that collapses to a bridge-served redirect.
    assert params["mode"] == "redirect"
    assert params["pattern"] == "*://example.com/*"
    assert params["redirect_url"] == f"http://127.0.0.1:9999/mock/{route_id}"
    assert bridge.mocks[route_id]["status"] == 200
    assert bridge.mocks[route_id]["body"] == b"ok"
    assert bridge.mocks[route_id]["headers"]["Content-Type"] == "text/plain"


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
    # The bridge URL is a driver-internal implementation detail and
    # must not surface in browser_route_list output.
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

    listed = drv.browser_route_list()
    ids = [r["route_id"] for r in listed["routes"]]
    # priority 10 first (high1 then high2 by insertion), then priority 1,
    # then default priority 0.
    assert ids == [r_high1, r_high2, r_low, r_default]


def test_unroute_by_route_id_returns_one() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    rid = drv.browser_route("*://example.com/*", body="x")["route_id"]
    assert rid in bridge.mocks
    bridge.calls.clear()
    bridge.mock_log.clear()

    result = drv.browser_unroute(route_id=rid)
    assert result == {"removed": 1}
    assert drv.browser_route_list() == {
        "routes": [],
        "count": 0,
        "total": 0,
        "truncated": False,
    }
    method, params = bridge.calls[-1]
    assert method == "route.remove"
    assert params["route_ids"] == [rid]
    assert rid not in bridge.mocks
    assert any(op == "unregister" and r == rid for op, r, _ in bridge.mock_log)


def test_unroute_by_route_id_unknown_returns_zero() -> None:
    drv = _Driver(bridge=_FakeBridge())
    assert drv.browser_unroute(route_id="missing") == {"removed": 0}


def test_unroute_by_pattern_removes_all_matching() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    rid_a = drv.browser_route("*://example.com/*", body="a")["route_id"]
    rid_b = drv.browser_route("*://example.com/*", body="b", priority=5)["route_id"]
    rid_c = drv.browser_route("*://other.com/*", body="c")["route_id"]
    bridge.calls.clear()
    bridge.mock_log.clear()

    result = drv.browser_unroute(pattern="*://example.com/*")
    assert result == {"removed": 2}
    remaining = drv.browser_route_list()["routes"]
    assert len(remaining) == 1
    assert remaining[0]["pattern"] == "*://other.com/*"
    method, params = bridge.calls[-1]
    assert method == "route.remove"
    assert set(params["route_ids"]) == {rid_a, rid_b}
    assert rid_a not in bridge.mocks
    assert rid_b not in bridge.mocks
    assert rid_c in bridge.mocks


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
    assert drv.browser_route_list() == {
        "routes": [],
        "count": 0,
        "total": 0,
        "truncated": False,
    }


def test_route_list_limit_and_file_output(tmp_path: Path) -> None:
    drv = _Driver(bridge=_FakeBridge())
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
