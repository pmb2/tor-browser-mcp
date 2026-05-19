"""Unit tests for the proxy-intercept replay primitives.

The applier (``_apply_replay_modifications``) and the
``browser_intercept_replay`` tool are exercised against real
``HTTPFlow`` fixtures from :mod:`mitmproxy.test.tflow` plus a hand-rolled
``ProxyManager`` stub. ``ProxyManager.replay_flow`` itself is covered by
the substrate-level tests where the cross-thread dispatch shape and
timeout behaviour matter.
"""

from __future__ import annotations

import asyncio
import base64
import threading
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from torbrowser_driver._proxy_intercept_primitives import (
    _ProxyInterceptCapabilityMixin,
    _apply_replay_modifications,
)
from torbrowser_driver._proxy_intercept_substrate import ProxyManager
from torbrowser_driver.exceptions import ProxyInterceptError

from tests.conftest import _StubProxyManager


_mitm_tflow = pytest.importorskip("mitmproxy.test.tflow")


# ---------------------------------------------------------------------------
# Flow factories
# ---------------------------------------------------------------------------


def _flow(method: str = "GET", url: str = "https://example.com/path", *,
          resp: bool = True, body: bytes | None = None):
    from mitmproxy.test import tflow

    flow = tflow.tflow(resp=resp)
    flow.request.method = method
    flow.request.url = url
    if body is not None:
        flow.request.content = body
    return flow


# ---------------------------------------------------------------------------
# _apply_replay_modifications
# ---------------------------------------------------------------------------


def test_apply_method_lowercase_is_uppercased() -> None:
    flow = _flow()
    _apply_replay_modifications(flow, method="post")
    assert flow.request.method == "POST"


def test_apply_method_rejects_unknown_verb() -> None:
    flow = _flow()
    with pytest.raises(ValueError):
        _apply_replay_modifications(flow, method="BREW")


def test_apply_url_valid_is_assigned() -> None:
    flow = _flow()
    _apply_replay_modifications(flow, url="https://example.org/new?x=1")
    assert flow.request.url == "https://example.org/new?x=1"
    assert flow.request.host == "example.org"


def test_apply_url_missing_scheme_raises() -> None:
    flow = _flow()
    with pytest.raises(ValueError):
        _apply_replay_modifications(flow, url="example.org/no-scheme")


def test_apply_url_missing_host_raises() -> None:
    flow = _flow()
    with pytest.raises(ValueError):
        _apply_replay_modifications(flow, url="https:///no-host")


def test_apply_http_version_valid_is_assigned() -> None:
    flow = _flow()
    _apply_replay_modifications(flow, http_version="HTTP/2.0")
    assert flow.request.http_version == "HTTP/2.0"


def test_apply_http_version_invalid_raises() -> None:
    flow = _flow()
    with pytest.raises(ValueError):
        _apply_replay_modifications(flow, http_version="HTTP/3")


def test_apply_set_request_headers_case_insensitive_replace() -> None:
    flow = _flow()
    flow.request.headers["User-Agent"] = "Mozilla/5.0"
    _apply_replay_modifications(
        flow, set_request_headers={"user-agent": "replay/1.0"}
    )
    values = flow.request.headers.get_all("User-Agent")
    assert values == ["replay/1.0"]


def test_apply_set_request_headers_adds_new_header() -> None:
    flow = _flow()
    _apply_replay_modifications(
        flow, set_request_headers={"X-Replay": "yes"}
    )
    assert flow.request.headers["X-Replay"] == "yes"


def test_apply_remove_request_headers_case_insensitive() -> None:
    flow = _flow()
    flow.request.headers["X-Trace"] = "abc"
    _apply_replay_modifications(flow, remove_request_headers=["x-trace"])
    assert "X-Trace" not in flow.request.headers
    assert "x-trace" not in flow.request.headers


def test_apply_remove_request_headers_missing_name_no_op() -> None:
    flow = _flow()
    _apply_replay_modifications(flow, remove_request_headers=["X-Nope"])
    # No raise.


def test_apply_body_str_utf8_encoded() -> None:
    flow = _flow()
    _apply_replay_modifications(flow, body="hello world")
    assert flow.request.content == b"hello world"


def test_apply_body_base64_decoded() -> None:
    flow = _flow()
    encoded = base64.b64encode(b"\x00\x01\x02").decode("ascii")
    _apply_replay_modifications(flow, body_base64=encoded)
    assert flow.request.content == b"\x00\x01\x02"


def test_apply_body_and_body_base64_simultaneously_raises() -> None:
    flow = _flow()
    with pytest.raises(ValueError):
        _apply_replay_modifications(
            flow, body="x", body_base64=base64.b64encode(b"y").decode()
        )


def test_apply_body_base64_invalid_raises() -> None:
    flow = _flow()
    with pytest.raises(ValueError):
        _apply_replay_modifications(flow, body_base64="not valid !!")


def test_apply_unknown_kwarg_raises() -> None:
    flow = _flow()
    with pytest.raises(ValueError) as exc:
        _apply_replay_modifications(flow, mehtod="GET")  # typo
    assert "mehtod" in str(exc.value)


def test_apply_cookie_header_preserved_when_not_overridden() -> None:
    flow = _flow()
    flow.request.headers["Cookie"] = "session=abc"
    _apply_replay_modifications(
        flow, set_request_headers={"User-Agent": "ua/1"}
    )
    assert flow.request.headers["Cookie"] == "session=abc"


def test_apply_cookie_header_overridden_when_set() -> None:
    flow = _flow()
    flow.request.headers["Cookie"] = "session=abc"
    _apply_replay_modifications(
        flow, set_request_headers={"cookie": "session=new"}
    )
    assert flow.request.headers.get_all("Cookie") == ["session=new"]


def test_apply_set_request_headers_rejects_non_dict() -> None:
    flow = _flow()
    with pytest.raises(ValueError):
        _apply_replay_modifications(
            flow, set_request_headers=[("X", "1")]  # type: ignore[arg-type]
        )


def test_apply_no_body_preserves_source_content() -> None:
    flow = _flow(body=b"original")
    _apply_replay_modifications(flow, method="POST")
    assert flow.request.content == b"original"


# ---------------------------------------------------------------------------
# browser_intercept_replay (mixin) via stub ProxyManager
# ---------------------------------------------------------------------------


class _StubManager(_StubProxyManager):
    """Replay-aware extension of the shared stub.

    Adds the ``replay_flow`` surface plus the bookkeeping attributes the
    replay tests poke at directly (``replay_calls`` to inspect dispatch,
    ``_replay_return_id`` to fake a custom returned id, ``_replay_raises``
    to simulate a failed dispatch).
    """

    def __init__(
        self,
        *,
        alive: bool = True,
        listen_port: int = 9261,
        max_flows: int = 1000,
    ) -> None:
        super().__init__(
            alive=alive, listen_port=listen_port, max_flows=max_flows
        )
        self.replay_calls: list[Any] = []
        self._replay_return_id: str | None = None
        self._replay_raises: Exception | None = None

    def replay_flow(self, flow: Any, timeout: float = 30.0) -> str:
        self.replay_calls.append((flow, timeout))
        if self._replay_raises is not None:
            raise self._replay_raises
        self.recorder.response(flow)
        return self._replay_return_id or flow.id


class _Driver(_ProxyInterceptCapabilityMixin):
    def __init__(self, manager: _StubManager | None) -> None:
        self._proxy_manager = manager
        self._proxy_ca_fingerprint = "deadbeef" * 8
        self.config = None  # type: ignore[assignment]


def test_replay_happy_path_returns_shape() -> None:
    mgr = _StubManager()
    source = _flow()
    mgr.recorder.response(source)
    drv = _Driver(mgr)

    result = drv.browser_intercept_replay(
        flow_id=source.id,
        set_request_headers={"User-Agent": "replay/1.0"},
    )

    assert set(result.keys()) == {
        "replay_flow_id", "source_flow_id", "since", "request"
    }
    assert result["source_flow_id"] == source.id
    assert result["replay_flow_id"] != source.id
    assert isinstance(result["since"], int)
    req = result["request"]
    assert req["method"] == source.request.method
    assert req["url"] == source.request.url
    assert req["http_version"] == source.request.http_version
    assert any(h[0].lower() == "user-agent" and h[1] == "replay/1.0"
               for h in req["headers"])


def test_replay_calls_manager_replay_with_copy() -> None:
    mgr = _StubManager()
    source = _flow()
    mgr.recorder.response(source)
    drv = _Driver(mgr)

    drv.browser_intercept_replay(flow_id=source.id, method="POST")

    assert len(mgr.replay_calls) == 1
    submitted, timeout = mgr.replay_calls[0]
    assert submitted is not source
    assert submitted.id != source.id
    assert submitted.request.method == "POST"
    assert timeout == 30.0


def test_replay_unknown_flow_id_raises_value_error() -> None:
    mgr = _StubManager()
    drv = _Driver(mgr)
    with pytest.raises(ValueError) as exc:
        drv.browser_intercept_replay(flow_id="no-such-id")
    assert "no-such-id" in str(exc.value)


def test_replay_synthetic_tls_failed_entry_raises_value_error() -> None:
    mgr = _StubManager()
    # Insert a synthetic tls_failed entry (no raw flow).
    mgr.recorder.tls_failed_client(object())
    drv = _Driver(mgr)
    fake_id = list(mgr.flow_buffer)[0]["id"]
    with pytest.raises(ValueError) as exc:
        drv.browser_intercept_replay(flow_id=fake_id)
    assert "synthetic" in str(exc.value) or "no raw flow" in str(exc.value)


def test_replay_does_not_mutate_source_flow() -> None:
    mgr = _StubManager()
    source = _flow(method="GET")
    mgr.recorder.response(source)
    drv = _Driver(mgr)

    drv.browser_intercept_replay(
        flow_id=source.id,
        method="POST",
        set_request_headers={"X-Replay": "yes"},
        body="new body",
    )

    assert source.request.method == "GET"
    assert "X-Replay" not in source.request.headers


def test_replay_rejects_dead_proxy() -> None:
    mgr = _StubManager(alive=False)
    drv = _Driver(mgr)
    with pytest.raises(ProxyInterceptError):
        drv.browser_intercept_replay(flow_id="any")


def test_replay_rejects_empty_flow_id() -> None:
    drv = _Driver(_StubManager())
    with pytest.raises(ValueError):
        drv.browser_intercept_replay(flow_id="")


def test_replay_rejects_non_positive_timeout() -> None:
    mgr = _StubManager()
    source = _flow()
    mgr.recorder.response(source)
    drv = _Driver(mgr)
    with pytest.raises(ValueError):
        drv.browser_intercept_replay(flow_id=source.id, timeout=0)
    with pytest.raises(ValueError):
        drv.browser_intercept_replay(flow_id=source.id, timeout=-1.0)


def test_replay_propagates_manager_proxy_intercept_error() -> None:
    mgr = _StubManager()
    source = _flow()
    mgr.recorder.response(source)
    mgr._replay_raises = ProxyInterceptError("replay did not complete within 5s")
    drv = _Driver(mgr)
    with pytest.raises(ProxyInterceptError) as exc:
        drv.browser_intercept_replay(flow_id=source.id, timeout=5.0)
    assert "did not complete" in str(exc.value)


def test_replay_timeout_propagated_to_manager() -> None:
    mgr = _StubManager()
    source = _flow()
    mgr.recorder.response(source)
    drv = _Driver(mgr)
    drv.browser_intercept_replay(flow_id=source.id, timeout=12.5)
    _, timeout = mgr.replay_calls[0]
    assert timeout == 12.5


# ---------------------------------------------------------------------------
# ProxyManager.replay_flow (heavily mocked)
# ---------------------------------------------------------------------------


def _build_running_loop_thread() -> tuple[asyncio.AbstractEventLoop, threading.Thread]:
    loop = asyncio.new_event_loop()

    def _runner() -> None:
        asyncio.set_event_loop(loop)
        loop.run_forever()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    # Wait until the loop is running.
    deadline = time.monotonic() + 2.0
    while not loop.is_running() and time.monotonic() < deadline:
        time.sleep(0.01)
    return loop, thread


def _stop_loop_thread(loop: asyncio.AbstractEventLoop,
                      thread: threading.Thread) -> None:
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=2.0)
    try:
        loop.close()
    except Exception:
        pass


def _make_manager_with_loop(loop: asyncio.AbstractEventLoop) -> ProxyManager:
    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=9999,
        socks_host="127.0.0.1",
        socks_port=9050,
    )
    mgr._loop = loop
    mgr._thread = threading.current_thread()  # appear alive

    class _FakeCommands:
        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple]] = []

        def call(self, name: str, *args: Any) -> None:
            self.calls.append((name, args))

    fake_master = MagicMock()
    fake_master.commands = _FakeCommands()
    mgr._master = fake_master
    mgr._started = True
    return mgr


def test_manager_replay_flow_dispatches_replay_client_command() -> None:
    loop, thread = _build_running_loop_thread()
    try:
        mgr = _make_manager_with_loop(loop)
        replay_flow = _flow()

        # Seed the recorder so flow_by_id sees the replay flow with a
        # response once it lands in the buffer.
        def _seed() -> None:
            time.sleep(0.05)
            mgr._recorder.response(replay_flow)

        threading.Thread(target=_seed, daemon=True).start()
        result_id = mgr.replay_flow(replay_flow, timeout=5.0)
        assert result_id == replay_flow.id
        assert mgr._master.commands.calls == [("replay.client", ([replay_flow],))]
    finally:
        _stop_loop_thread(loop, thread)


def test_manager_replay_flow_times_out_with_proxy_intercept_error() -> None:
    loop, thread = _build_running_loop_thread()
    try:
        mgr = _make_manager_with_loop(loop)
        replay_flow = _flow()
        # Recorder is never seeded -> the poll loop should hit the deadline.
        with pytest.raises(ProxyInterceptError) as exc:
            mgr.replay_flow(replay_flow, timeout=0.3)
        assert "did not complete" in str(exc.value)
    finally:
        _stop_loop_thread(loop, thread)


def test_manager_replay_flow_rejects_when_substrate_down() -> None:
    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=9999,
        socks_host="127.0.0.1",
        socks_port=9050,
    )
    # _loop and _master remain None, is_alive() returns False.
    with pytest.raises(ProxyInterceptError):
        mgr.replay_flow(_flow(), timeout=1.0)
