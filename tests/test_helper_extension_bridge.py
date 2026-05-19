"""Unit tests for the helper-extension HTTP long-poll bridge.

The tests drive the bridge with stdlib ``http.client`` acting as the
extension side. No third-party HTTP library is used, so the bridge is
exercised end-to-end including auth, framing, and shutdown.
"""

from __future__ import annotations

import http.client
import json
import secrets
import socket
import threading
import time

import pytest

from torbrowser_driver import _helper_extension_bridge as bridge_module
from torbrowser_driver._helper_extension_bridge import HelperBridge
from torbrowser_driver.exceptions import (
    HelperBridgeDisconnected,
    HelperBridgeTimeout,
)


def _pick_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


@pytest.fixture
def bridge_factory(monkeypatch: pytest.MonkeyPatch):
    # Shorten the poll budget so idle tests don't sleep for 25 seconds.
    monkeypatch.setattr(bridge_module, "_POLL_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setattr(bridge_module, "_POLL_TICK_SECONDS", 0.05)

    bridges: list[HelperBridge] = []

    def _make(token: str | None = None) -> HelperBridge:
        port = _pick_port()
        b = HelperBridge(
            host="127.0.0.1",
            port=port,
            token=token or secrets.token_hex(16),
        )
        b.start()
        bridges.append(b)
        return b

    yield _make

    for b in bridges:
        b.close()


def _http(bridge: HelperBridge, timeout: float = 5.0) -> http.client.HTTPConnection:
    return http.client.HTTPConnection(bridge.host, bridge.port, timeout=timeout)


def _auth_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _hello(bridge: HelperBridge, token: str | None = None) -> http.client.HTTPResponse:
    conn = _http(bridge)
    payload = json.dumps(
        {"token": token if token is not None else bridge.token, "version": "0.1.0"}
    )
    conn.request(
        "POST",
        "/hello",
        body=payload,
        headers=_auth_headers(token if token is not None else bridge.token),
    )
    return conn.getresponse()


def _wait_connected(bridge: HelperBridge, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if bridge.connected:
            return
        time.sleep(0.01)
    raise AssertionError("bridge did not become connected")


def test_hello_accepts_valid_token(bridge_factory) -> None:
    bridge = bridge_factory()
    resp = _hello(bridge)
    assert resp.status == 200
    body = json.loads(resp.read().decode("utf-8"))
    assert body == {"ok": True, "session": bridge.token}
    _wait_connected(bridge)
    assert bridge.connected is True


def test_hello_rejects_bad_token(bridge_factory) -> None:
    bridge = bridge_factory(token="correct-token")
    conn = _http(bridge)
    conn.request(
        "POST",
        "/hello",
        body=json.dumps({"token": "wrong", "version": "x"}),
        headers=_auth_headers("wrong-token"),
    )
    resp = conn.getresponse()
    assert resp.status == 401
    resp.read()
    assert bridge.connected is False


def test_unauthenticated_request_rejected(bridge_factory) -> None:
    bridge = bridge_factory()
    conn = _http(bridge)
    conn.request("POST", "/hello", body="{}", headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 401
    resp.read()


def test_request_response_roundtrip(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)

    def poll_and_respond() -> None:
        conn = _http(bridge)
        conn.request("GET", "/poll", headers=_auth_headers(bridge.token))
        resp = conn.getresponse()
        assert resp.status == 200
        req = json.loads(resp.read().decode("utf-8"))
        body = json.dumps({"id": req["id"], "result": {"echoed": req["method"]}})
        conn2 = _http(bridge)
        conn2.request("POST", "/response", body=body, headers=_auth_headers(bridge.token))
        conn2.getresponse().read()

    t = threading.Thread(target=poll_and_respond, daemon=True)
    t.start()
    result = bridge.request("ping", {"x": 1}, timeout=3.0)
    t.join(timeout=3.0)
    assert result == {"echoed": "ping"}


def test_request_demux_concurrent(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)

    method_to_id: dict[str, int] = {}
    lock = threading.Lock()

    def poll_worker() -> None:
        conn = _http(bridge)
        conn.request("GET", "/poll", headers=_auth_headers(bridge.token))
        resp = conn.getresponse()
        if resp.status != 200:
            return
        req = json.loads(resp.read().decode("utf-8"))
        with lock:
            method_to_id[req["method"]] = req["id"]
        # Slow first responder so the second request must overlap.
        time.sleep(0.05)
        body = json.dumps(
            {"id": req["id"], "result": {"method": req["method"]}}
        )
        conn2 = _http(bridge)
        conn2.request("POST", "/response", body=body, headers=_auth_headers(bridge.token))
        conn2.getresponse().read()

    workers = [threading.Thread(target=poll_worker, daemon=True) for _ in range(2)]
    for w in workers:
        w.start()
    # Give the pollers a moment to block in /poll so the queue.get is parked.
    time.sleep(0.05)

    results: dict[str, dict] = {}

    def fire(method: str) -> None:
        results[method] = bridge.request(method, {}, timeout=3.0)

    t1 = threading.Thread(target=fire, args=("alpha",))
    t2 = threading.Thread(target=fire, args=("beta",))
    t1.start()
    t2.start()
    t1.join(timeout=4.0)
    t2.join(timeout=4.0)
    for w in workers:
        w.join(timeout=2.0)

    assert results["alpha"] == {"method": "alpha"}
    assert results["beta"] == {"method": "beta"}
    assert method_to_id["alpha"] != method_to_id["beta"]


def test_request_timeout_raises(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)
    with pytest.raises(HelperBridgeTimeout):
        bridge.request("never-answered", {}, timeout=0.2)


def test_request_after_close_raises(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)
    bridge.close()
    with pytest.raises(HelperBridgeDisconnected):
        bridge.request("any", {}, timeout=1.0)


def test_request_after_disconnect_raises(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)
    # Simulate the watchdog flipping the bridge to disconnected.
    with bridge._state_lock:
        bridge._connected = False
    with pytest.raises(HelperBridgeDisconnected):
        bridge.request("any", {}, timeout=1.0)


def test_event_dispatched_to_subscriber(bridge_factory) -> None:
    bridge = bridge_factory()
    received: list[dict] = []
    bridge.subscribe("ping.tick", lambda payload: received.append(payload))
    _hello(bridge).read()
    _wait_connected(bridge)

    conn = _http(bridge)
    conn.request(
        "POST",
        "/event",
        body=json.dumps({"name": "ping.tick", "data": {"n": 7}}),
        headers=_auth_headers(bridge.token),
    )
    resp = conn.getresponse()
    assert resp.status == 204
    resp.read()

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and not received:
        time.sleep(0.01)
    assert received == [{"n": 7}]


def test_poll_returns_204_when_idle(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)

    conn = _http(bridge, timeout=5.0)
    started = time.monotonic()
    conn.request("GET", "/poll", headers=_auth_headers(bridge.token))
    resp = conn.getresponse()
    elapsed = time.monotonic() - started
    assert resp.status == 204
    resp.read()
    # The shortened poll budget is 0.5 s; idle return must respect it.
    assert 0.3 <= elapsed < 3.0, f"unexpected poll wall-clock: {elapsed:.2f}s"


def test_concurrent_polls_each_get_their_own_request(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)

    collected: list[dict] = []
    lock = threading.Lock()

    def poll_once() -> None:
        conn = _http(bridge, timeout=5.0)
        conn.request("GET", "/poll", headers=_auth_headers(bridge.token))
        resp = conn.getresponse()
        if resp.status != 200:
            return
        msg = json.loads(resp.read().decode("utf-8"))
        with lock:
            collected.append(msg)

    pollers = [threading.Thread(target=poll_once, daemon=True) for _ in range(2)]
    for p in pollers:
        p.start()
    time.sleep(0.05)

    responses: dict[str, dict] = {}

    def fire_and_respond(method: str) -> None:
        # Reply on a background thread once the request has surfaced.
        def responder() -> None:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                with lock:
                    match = next((m for m in collected if m["method"] == method), None)
                if match is not None:
                    body = json.dumps({"id": match["id"], "result": {"ok": method}})
                    conn = _http(bridge)
                    conn.request(
                        "POST",
                        "/response",
                        body=body,
                        headers=_auth_headers(bridge.token),
                    )
                    conn.getresponse().read()
                    return
                time.sleep(0.01)

        threading.Thread(target=responder, daemon=True).start()
        responses[method] = bridge.request(method, {}, timeout=3.0)

    t1 = threading.Thread(target=fire_and_respond, args=("alpha",))
    t2 = threading.Thread(target=fire_and_respond, args=("beta",))
    t1.start()
    t2.start()
    t1.join(timeout=4.0)
    t2.join(timeout=4.0)
    for p in pollers:
        p.join(timeout=2.0)

    methods = sorted(m["method"] for m in collected)
    assert methods == ["alpha", "beta"]
    assert responses["alpha"] == {"ok": "alpha"}
    assert responses["beta"] == {"ok": "beta"}


def test_close_unblocks_pending_polls(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)

    status_box: list[int] = []
    elapsed_box: list[float] = []

    def poll() -> None:
        conn = _http(bridge, timeout=5.0)
        started = time.monotonic()
        try:
            conn.request("GET", "/poll", headers=_auth_headers(bridge.token))
            resp = conn.getresponse()
            elapsed_box.append(time.monotonic() - started)
            status_box.append(resp.status)
            resp.read()
        except Exception:
            elapsed_box.append(time.monotonic() - started)

    t = threading.Thread(target=poll, daemon=True)
    t.start()
    # Let the poll get parked inside _wait_for_outgoing.
    time.sleep(0.05)
    bridge.close()
    t.join(timeout=3.0)
    assert elapsed_box, "poller never returned"
    # close() should unblock within one tick (_POLL_TICK_SECONDS=0.05),
    # not wait out the full poll budget.
    assert elapsed_box[0] < 1.0, f"close did not unblock poll quickly: {elapsed_box[0]:.2f}s"


def test_mock_endpoint_is_no_longer_served(bridge_factory) -> None:
    bridge = bridge_factory()
    conn = _http(bridge)
    conn.request("GET", "/mock/" + "a" * 32)
    resp = conn.getresponse()
    resp.read()
    # Mock-fulfill moved to the proxy-intercept substrate; the bridge
    # no longer exposes /mock/* and the path falls through to 401
    # (unauthenticated) instead of being served.
    assert resp.status == 401


def test_request_after_disconnect_during_request_raises(bridge_factory) -> None:
    bridge = bridge_factory()
    _hello(bridge).read()
    _wait_connected(bridge)

    error_box: list[BaseException] = []

    def fire() -> None:
        try:
            bridge.request("hang", {}, timeout=5.0)
        except BaseException as exc:
            error_box.append(exc)

    t = threading.Thread(target=fire, daemon=True)
    t.start()
    time.sleep(0.05)
    bridge.close()
    t.join(timeout=3.0)
    assert error_box, "request thread never raised"
    assert isinstance(error_box[0], HelperBridgeDisconnected)
