"""Unit tests for the proxy-intercept substrate.

These tests mock the mitmproxy ``DumpMaster`` boundary so they do not
require a real listener to boot. A separate set of tests against the
inline ``FlowRecorder`` addon uses real ``mitmproxy.http.HTTPFlow``
objects built via ``mitmproxy.test.tflow`` so the serialisation shape
is exercised against the version of mitmproxy actually installed.
"""

from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import patch

import pytest

from torbrowser_driver._proxy_intercept_substrate import (
    FlowRecorder,
    ProxyManager,
)
from torbrowser_driver.exceptions import ProxyInterceptError


_mitm = pytest.importorskip("mitmproxy.test.tflow")
_mitm_http = pytest.importorskip("mitmproxy.http")


class _FakeAddons:
    def __init__(self) -> None:
        self.added: list = []

    def add(self, *addons) -> None:
        self.added.extend(addons)


class _FakeMaster:
    """Stand-in for mitmproxy.tools.dump.DumpMaster.

    Models the surface ``ProxyManager`` touches: an ``addons.add(...)``
    accumulator, an awaitable ``run()`` that blocks until ``shutdown()``
    is called, and a synchronous ``shutdown()`` that unblocks the run.
    """

    instances: list["_FakeMaster"] = []

    def __init__(self, opts, with_termlog=True, with_dumper=True) -> None:
        self.options = opts
        self.with_termlog = with_termlog
        self.with_dumper = with_dumper
        self.addons = _FakeAddons()
        self._shutdown_event: asyncio.Event | None = None
        self.run_called = False
        self.shutdown_called = False
        _FakeMaster.instances.append(self)

    async def run(self) -> None:
        self.run_called = True
        self._shutdown_event = asyncio.Event()
        await self._shutdown_event.wait()

    def shutdown(self) -> None:
        self.shutdown_called = True
        if self._shutdown_event is not None:
            loop = self._shutdown_event._loop  # type: ignore[attr-defined]
            try:
                loop.call_soon_threadsafe(self._shutdown_event.set)
            except RuntimeError:
                pass


@pytest.fixture(autouse=True)
def _reset_fake_master():
    _FakeMaster.instances.clear()
    yield
    _FakeMaster.instances.clear()


def _patched_build_master(adapter_port: int):
    return _FakeMaster(opts=None)


@pytest.fixture
def patched_build():
    with patch.object(ProxyManager, "_build_master", lambda self, p: _FakeMaster(opts=None)):
        yield


def test_start_brings_thread_alive_and_stop_joins(patched_build) -> None:
    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host="127.0.0.1",
        socks_port=1,
    )
    mgr.start(timeout=5.0)
    try:
        assert mgr.is_alive() is True
        assert mgr.socks_adapter_port > 0
        # Master was constructed inside the daemon's loop.
        assert _FakeMaster.instances, "fake master was not constructed"
    finally:
        mgr.stop(timeout=5.0)
    assert mgr.is_alive() is False


def test_stop_is_idempotent(patched_build) -> None:
    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host="127.0.0.1",
        socks_port=1,
    )
    mgr.start(timeout=5.0)
    mgr.stop(timeout=5.0)
    mgr.stop(timeout=5.0)
    assert mgr.is_alive() is False


def test_double_start_raises(patched_build) -> None:
    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host="127.0.0.1",
        socks_port=1,
    )
    mgr.start(timeout=5.0)
    try:
        with pytest.raises(ProxyInterceptError):
            mgr.start(timeout=5.0)
    finally:
        mgr.stop(timeout=5.0)


def test_stop_before_start_is_noop() -> None:
    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host="127.0.0.1",
        socks_port=1,
    )
    # Must not raise; must leave the manager in a stopped state.
    mgr.stop(timeout=1.0)
    assert mgr.is_alive() is False


def test_stop_dispatches_via_run_coroutine_threadsafe(patched_build) -> None:
    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host="127.0.0.1",
        socks_port=1,
    )
    mgr.start(timeout=5.0)
    try:
        with patch(
            "torbrowser_driver._proxy_intercept_substrate.asyncio.run_coroutine_threadsafe",
            wraps=asyncio.run_coroutine_threadsafe,
        ) as spy:
            mgr.stop(timeout=5.0)
        assert spy.call_count >= 1
        # Second positional arg is the loop owned by the daemon.
        loop_arg = spy.call_args.args[1]
        assert isinstance(loop_arg, asyncio.AbstractEventLoop)
    finally:
        mgr.stop(timeout=5.0)


def test_socks_adapter_port_before_start_raises() -> None:
    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host="127.0.0.1",
        socks_port=1,
    )
    with pytest.raises(ProxyInterceptError):
        _ = mgr.socks_adapter_port


def test_start_propagates_master_build_failure() -> None:
    class _Boom:
        def __init__(self, *a, **k) -> None:
            raise RuntimeError("boom from fake master")

    mgr = ProxyManager(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host="127.0.0.1",
        socks_port=1,
    )
    with patch.object(ProxyManager, "_build_master", lambda self, p: _Boom()):
        with pytest.raises(ProxyInterceptError):
            mgr.start(timeout=5.0)
    # last_error surfaces the underlying RuntimeError.
    last = mgr.last_error()
    assert isinstance(last, RuntimeError)
    assert "boom from fake master" in str(last)


# ---------------------------------------------------------------------------
# FlowRecorder shape and bookkeeping.
# ---------------------------------------------------------------------------


def _make_flow_with_response():
    from mitmproxy.test import tflow

    return tflow.tflow(resp=True)


def _make_flow_no_response():
    from mitmproxy.test import tflow

    return tflow.tflow()


def _make_flow_with_error():
    from mitmproxy.test import tflow

    return tflow.tflow(err=True)


def test_recorder_evicts_at_max_flows() -> None:
    recorder = FlowRecorder(max_flows=5)
    for _ in range(8):
        recorder.request(_make_flow_no_response())
    buf = recorder.buffer
    assert len(buf) == 5
    # Monotonic ``since`` across all 8 inserts.
    assert recorder.next_since == 8
    # The remaining buffer carries the most recent five ``since`` values.
    since_values = [entry["since"] for entry in buf]
    assert since_values == [3, 4, 5, 6, 7]


def test_recorder_next_since_is_monotonic() -> None:
    recorder = FlowRecorder(max_flows=100)
    assert recorder.next_since == 0
    recorder.request(_make_flow_no_response())
    assert recorder.next_since == 1
    recorder.request(_make_flow_no_response())
    assert recorder.next_since == 2


def test_serialise_request_only_flow_shape() -> None:
    recorder = FlowRecorder(max_flows=10)
    flow = _make_flow_no_response()
    recorder.request(flow)
    entry = recorder.buffer[-1]

    assert entry["id"] == flow.id
    assert isinstance(entry["since"], int)
    assert entry["response"] is None
    assert entry["error"] is None

    req = entry["request"]
    assert req["method"] == flow.request.method
    assert req["url"] == flow.request.url
    assert req["scheme"] == flow.request.scheme
    assert req["host"] == flow.request.host
    assert req["port"] == flow.request.port
    assert req["path"] == flow.request.path
    assert req["http_version"] == flow.request.http_version
    assert isinstance(req["headers"], list)
    for item in req["headers"]:
        assert isinstance(item, list)
        assert len(item) == 2
    assert req["timestamp_start"] == flow.request.timestamp_start
    # ``timestamp_end`` may legitimately be ``None`` for an in-flight request.
    assert "timestamp_end" in req

    addr = entry["server_address"]
    if addr is not None:
        assert isinstance(addr, tuple)
        assert len(addr) == 2
        assert isinstance(addr[0], str)
        assert isinstance(addr[1], int)


def test_serialise_response_shape() -> None:
    recorder = FlowRecorder(max_flows=10)
    flow = _make_flow_with_response()
    recorder.response(flow)
    entry = recorder.buffer[-1]
    resp = entry["response"]
    assert resp is not None
    assert resp["status_code"] == flow.response.status_code
    assert resp["reason"] == flow.response.reason
    assert resp["http_version"] == flow.response.http_version
    assert isinstance(resp["headers"], list)
    assert resp["timestamp_start"] == flow.response.timestamp_start
    assert resp["timestamp_end"] == flow.response.timestamp_end
    assert isinstance(resp["content_length"], int)
    assert resp["content_length"] >= 0


def test_serialise_error_shape() -> None:
    recorder = FlowRecorder(max_flows=10)
    flow = _make_flow_with_error()
    recorder.error(flow)
    entry = recorder.buffer[-1]
    err = entry["error"]
    assert err is not None
    assert err["msg"] == flow.error.msg
    assert err["timestamp"] == flow.error.timestamp


def test_repeat_hook_for_same_flow_updates_in_place() -> None:
    """A single flow that fires ``request`` then ``response`` lands as one
    buffer entry with both halves populated, not two separate entries."""

    recorder = FlowRecorder(max_flows=10)
    flow = _make_flow_with_response()
    recorder.request(flow)
    first_since = recorder.buffer[-1]["since"]
    recorder.response(flow)
    matching = [e for e in recorder.buffer if e["id"] == flow.id]
    assert len(matching) == 1
    assert matching[0]["request"] is not None
    assert matching[0]["response"] is not None
    # ``since`` is the insertion index; updates do not bump it.
    assert matching[0]["since"] == first_since


def test_tls_failed_client_appends_synthetic_entry() -> None:
    recorder = FlowRecorder(max_flows=10)

    class _Data:
        class context:
            client = "stand-in-client"

        class conn:
            sni = "example.com"

    recorder.tls_failed_client(_Data())
    entry = recorder.buffer[-1]
    assert entry["request"] is None
    assert entry["response"] is None
    assert entry["error"] is not None
    assert entry["error"]["msg"] == "tls_failed_client"
    assert entry["tls_failed"]["sni"] == "example.com"


def test_recorder_max_flows_validates() -> None:
    with pytest.raises(ProxyInterceptError):
        FlowRecorder(max_flows=0)
