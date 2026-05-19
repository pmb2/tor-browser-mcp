"""Unit tests for the proxy-intercept observation primitives.

The mixin is exercised against a hand-rolled stand-in for
:class:`ProxyManager` so these tests do not boot the daemon thread or
talk to mitmproxy's master. Raw flow fixtures come from
``mitmproxy.test.tflow`` so the body-augmentation paths run against
real ``HTTPFlow`` objects.
"""

from __future__ import annotations

import io
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from torbrowser_driver._proxy_intercept_primitives import (
    _ProxyInterceptCapabilityMixin,
    _decode_body,
)
from torbrowser_driver.exceptions import ProxyInterceptError

from tests.conftest import _StubProxyManager as _StubManager


_mitm_tflow = pytest.importorskip("mitmproxy.test.tflow")
_mitm_io = pytest.importorskip("mitmproxy.io")


# ---------------------------------------------------------------------------
# Stand-ins
# ---------------------------------------------------------------------------


class _StubPathPolicy:
    def __init__(self, root: Path) -> None:
        self.output_dir = root

    def resolve_output(self, name: str) -> Path:
        path = self.output_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


class _StubConfig:
    def __init__(self, root: Path) -> None:
        self.path_policy = _StubPathPolicy(root)


class _Driver(_ProxyInterceptCapabilityMixin):
    def __init__(
        self,
        manager: _StubManager | None,
        config: _StubConfig | None = None,
        fingerprint: str = "deadbeef" * 8,
    ) -> None:
        self._proxy_manager = manager
        self._proxy_ca_fingerprint = fingerprint
        self.config = config  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Flow factories
# ---------------------------------------------------------------------------


def _flow_with_text_body(text: str = "hello world"):
    from mitmproxy.test import tflow

    flow = tflow.tflow(resp=True)
    flow.response.set_content(text.encode("utf-8"))
    return flow


def _flow_with_binary_body(data: bytes):
    from mitmproxy.test import tflow

    flow = tflow.tflow(resp=True)
    flow.response.set_content(data)
    return flow


def _flow_no_response():
    from mitmproxy.test import tflow

    return tflow.tflow()


def _flow_with_error():
    from mitmproxy.test import tflow

    return tflow.tflow(err=True)


def _flow_with_host(host: str, status: int = 200):
    from mitmproxy.test import tflow

    flow = tflow.tflow(resp=True)
    flow.request.host = host
    flow.response.status_code = status
    return flow


# ---------------------------------------------------------------------------
# decode_body helper
# ---------------------------------------------------------------------------


def test_decode_body_utf8_passthrough() -> None:
    body, truncated = _decode_body(b"hello world", max_body_bytes=1024)
    assert body == "hello world"
    assert truncated is False


def test_decode_body_non_utf8_base64() -> None:
    raw = b"\xff\xfe\x00\x01"
    body, truncated = _decode_body(raw, max_body_bytes=1024)
    assert isinstance(body, dict) and "base64" in body
    assert truncated is False


def test_decode_body_truncates_to_cap() -> None:
    raw = b"a" * 4096
    body, truncated = _decode_body(raw, max_body_bytes=1024)
    assert truncated is True
    assert isinstance(body, str)
    assert len(body) == 1024


# ---------------------------------------------------------------------------
# _proxy_alive_check
# ---------------------------------------------------------------------------


def test_alive_check_raises_without_manager() -> None:
    drv = _Driver(manager=None)
    with pytest.raises(ProxyInterceptError) as exc:
        drv._proxy_alive_check()
    assert "not enabled" in str(exc.value)


def test_alive_check_raises_when_dead() -> None:
    mgr = _StubManager(alive=False, last_error=RuntimeError("boom"))
    drv = _Driver(mgr)
    with pytest.raises(ProxyInterceptError) as exc:
        drv._proxy_alive_check()
    assert "down" in str(exc.value)
    assert "RuntimeError" in str(exc.value) or "boom" in str(exc.value)


def test_alive_check_passes_when_alive() -> None:
    mgr = _StubManager(alive=True)
    drv = _Driver(mgr)
    drv._proxy_alive_check()  # must not raise


# ---------------------------------------------------------------------------
# start / stop round-trip
# ---------------------------------------------------------------------------


def test_start_returns_cursor_and_fingerprint() -> None:
    mgr = _StubManager(listen_port=9261)
    mgr.recorder.request(_flow_no_response())
    mgr.recorder.request(_flow_no_response())
    drv = _Driver(mgr, fingerprint="abc123")
    result = drv.browser_intercept_start()
    assert result == {
        "started": True,
        "intercept_port": 9261,
        "ca_fingerprint": "abc123",
        "since": 2,
    }


def test_start_raises_when_proxy_down() -> None:
    drv = _Driver(_StubManager(alive=False))
    with pytest.raises(ProxyInterceptError):
        drv.browser_intercept_start()


def test_stop_clears_buffer_and_returns_count() -> None:
    mgr = _StubManager()
    for _ in range(3):
        mgr.recorder.request(_flow_no_response())
    drv = _Driver(mgr)
    result = drv.browser_intercept_stop()
    assert result == {"stopped": True, "flows_collected": 3}
    assert list(mgr.flow_buffer) == []
    assert mgr.next_since == 0


def test_start_after_stop_returns_zero_cursor() -> None:
    mgr = _StubManager()
    mgr.recorder.request(_flow_no_response())
    drv = _Driver(mgr)
    drv.browser_intercept_stop()
    result = drv.browser_intercept_start()
    assert result["since"] == 0


# ---------------------------------------------------------------------------
# browser_intercept_flows: filtering + body handling
# ---------------------------------------------------------------------------


def test_flows_strips_bodies_by_default() -> None:
    mgr = _StubManager()
    mgr.recorder.response(_flow_with_text_body("hello"))
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows()
    assert len(result["flows"]) == 1
    entry = result["flows"][0]
    assert "body" not in entry["request"]
    assert "body" not in (entry["response"] or {})
    assert entry["request"]["request_body_truncated"] is True
    assert entry["response"]["response_body_truncated"] is True


def test_flows_includes_text_body_when_requested() -> None:
    mgr = _StubManager()
    mgr.recorder.response(_flow_with_text_body("hello world"))
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(include_bodies=True)
    assert result["flows"][0]["response"]["body"] == "hello world"


def test_flows_truncates_large_body() -> None:
    mgr = _StubManager()
    big = _flow_with_binary_body(b"A" * (10 * 1024 * 1024))
    mgr.recorder.response(big)
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(
        include_bodies=True, max_body_bytes=1024
    )
    entry = result["flows"][0]
    body = entry["response"]["body"]
    assert isinstance(body, str)
    assert len(body) == 1024
    assert entry["response"]["response_body_truncated"] is True


def test_flows_non_utf8_body_returns_base64_envelope() -> None:
    mgr = _StubManager()
    mgr.recorder.response(_flow_with_binary_body(b"\xff\xfe\x00\x01"))
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(include_bodies=True)
    body = result["flows"][0]["response"]["body"]
    assert isinstance(body, dict)
    assert "base64" in body


def test_flows_filters_by_host_substring_case_insensitive() -> None:
    mgr = _StubManager()
    mgr.recorder.response(_flow_with_host("alpha.example.com"))
    mgr.recorder.response(_flow_with_host("beta.example.com"))
    mgr.recorder.response(_flow_with_host("unrelated.test"))
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(host="EXAMPLE.COM")
    hosts = sorted(e["request"]["host"] for e in result["flows"])
    assert hosts == ["alpha.example.com", "beta.example.com"]


def test_flows_filters_by_status_code_exact_match_skips_error_only() -> None:
    mgr = _StubManager()
    mgr.recorder.response(_flow_with_host("a.example", status=200))
    mgr.recorder.response(_flow_with_host("b.example", status=404))
    mgr.recorder.error(_flow_with_error())  # response is None
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(status_code=200)
    assert len(result["flows"]) == 1
    assert result["flows"][0]["request"]["host"] == "a.example"


def test_flows_since_cursor_only_returns_newer() -> None:
    mgr = _StubManager()
    for _ in range(5):
        mgr.recorder.request(_flow_no_response())
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(since=2)
    sinces = [e["since"] for e in result["flows"]]
    assert sinces == [3, 4]
    assert result["next_since"] == 4


def test_flows_since_zero_returns_all_after_zero() -> None:
    mgr = _StubManager()
    for _ in range(3):
        mgr.recorder.request(_flow_no_response())
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(since=0)
    # since=0 means strictly greater than 0; entries 1 and 2.
    sinces = [e["since"] for e in result["flows"]]
    assert sinces == [1, 2]


def test_flows_limit_caps_and_marks_truncated() -> None:
    mgr = _StubManager()
    for _ in range(10):
        mgr.recorder.request(_flow_no_response())
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(limit=3)
    assert len(result["flows"]) == 3
    assert result["truncated"] is True


def test_flows_no_filter_match_returns_empty_and_next_since_input() -> None:
    mgr = _StubManager()
    mgr.recorder.response(_flow_with_host("alpha.example.com"))
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(host="absent")
    assert result["flows"] == []
    assert result["truncated"] is False


def test_flows_raises_on_dead_proxy() -> None:
    mgr = _StubManager(alive=False)
    drv = _Driver(mgr)
    with pytest.raises(ProxyInterceptError):
        drv.browser_intercept_flows()


def test_flows_rejects_negative_limit() -> None:
    drv = _Driver(_StubManager())
    with pytest.raises(ValueError):
        drv.browser_intercept_flows(limit=-1)


def test_flows_rejects_non_int_since() -> None:
    drv = _Driver(_StubManager())
    with pytest.raises(ValueError):
        drv.browser_intercept_flows(since="0")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# browser_intercept_flow (single)
# ---------------------------------------------------------------------------


def test_flow_lookup_returns_full_entry_with_body() -> None:
    mgr = _StubManager()
    flow = _flow_with_text_body("payload")
    mgr.recorder.response(flow)
    drv = _Driver(mgr)
    entry = drv.browser_intercept_flow(flow_id=flow.id)
    assert entry["id"] == flow.id
    assert entry["response"]["body"] == "payload"


def test_flow_lookup_without_bodies_marks_truncation() -> None:
    mgr = _StubManager()
    flow = _flow_with_text_body("payload")
    mgr.recorder.response(flow)
    drv = _Driver(mgr)
    entry = drv.browser_intercept_flow(
        flow_id=flow.id, include_bodies=False
    )
    assert "body" not in entry["response"]
    assert entry["response"]["response_body_truncated"] is True


def test_flow_lookup_unknown_id_raises_value_error() -> None:
    mgr = _StubManager()
    mgr.recorder.request(_flow_no_response())
    drv = _Driver(mgr)
    with pytest.raises(ValueError):
        drv.browser_intercept_flow(flow_id="does-not-exist")


def test_flow_lookup_rejects_empty_id() -> None:
    drv = _Driver(_StubManager())
    with pytest.raises(ValueError):
        drv.browser_intercept_flow(flow_id="")


def test_flow_lookup_raises_on_dead_proxy() -> None:
    drv = _Driver(_StubManager(alive=False))
    with pytest.raises(ProxyInterceptError):
        drv.browser_intercept_flow(flow_id="anything")


# ---------------------------------------------------------------------------
# browser_intercept_save
# ---------------------------------------------------------------------------


def test_save_writes_real_mitmproxy_archive(tmp_path: Path) -> None:
    mgr = _StubManager()
    flow1 = _flow_with_text_body("alpha")
    flow2 = _flow_with_text_body("beta")
    mgr.recorder.response(flow1)
    mgr.recorder.response(flow2)
    drv = _Driver(mgr, config=_StubConfig(tmp_path))
    result = drv.browser_intercept_save(path="capture.flows")
    out = Path(result["path"])
    assert out.is_file()
    assert out.stat().st_size > 0
    assert result["flow_count"] == 2

    with open(out, "rb") as fh:
        reader = _mitm_io.FlowReader(fh)
        flows = list(reader.stream())
    assert len(flows) == 2
    assert {f.id for f in flows} == {flow1.id, flow2.id}


def test_save_routes_through_path_policy(tmp_path: Path) -> None:
    mgr = _StubManager()
    mgr.recorder.response(_flow_with_text_body("a"))
    drv = _Driver(mgr, config=_StubConfig(tmp_path))

    with patch.object(
        _StubPathPolicy,
        "resolve_output",
        wraps=drv.config.path_policy.resolve_output,
    ) as spy:
        result = drv.browser_intercept_save(path="sub/dir/flows.bin")
    assert spy.call_count == 1
    assert spy.call_args.args == ("sub/dir/flows.bin",)
    out = Path(result["path"])
    assert out.is_file()
    assert out.parent.name == "dir"


def test_save_rejects_empty_path(tmp_path: Path) -> None:
    drv = _Driver(_StubManager(), config=_StubConfig(tmp_path))
    with pytest.raises(ValueError):
        drv.browser_intercept_save(path="")


def test_save_raises_when_resolve_output_rejects(tmp_path: Path) -> None:
    class _RejectingPolicy:
        output_dir = tmp_path

        def resolve_output(self, name: str) -> Path:
            from torbrowser_driver.exceptions import PathNotAllowed

            raise PathNotAllowed(f"refusing {name!r}")

    cfg = SimpleNamespace(path_policy=_RejectingPolicy())
    mgr = _StubManager()
    mgr.recorder.response(_flow_with_text_body("a"))
    drv = _Driver(mgr)
    drv.config = cfg  # type: ignore[assignment]
    from torbrowser_driver.exceptions import PathNotAllowed

    with pytest.raises(PathNotAllowed):
        drv.browser_intercept_save(path="../escape.flows")


def test_save_raises_on_dead_proxy(tmp_path: Path) -> None:
    drv = _Driver(_StubManager(alive=False), config=_StubConfig(tmp_path))
    with pytest.raises(ProxyInterceptError):
        drv.browser_intercept_save(path="x.flows")


# ---------------------------------------------------------------------------
# Flow shape coverage against tflow factories
# ---------------------------------------------------------------------------


def test_request_only_flow_shape() -> None:
    mgr = _StubManager()
    flow = _flow_no_response()
    mgr.recorder.request(flow)
    drv = _Driver(mgr)
    result = drv.browser_intercept_flows(include_bodies=True)
    entry = result["flows"][0]
    assert entry["response"] is None
    assert entry["request"]["method"] == flow.request.method
    assert entry["request"]["host"] == flow.request.host
    assert isinstance(entry["request"]["headers"], list)


def test_error_only_flow_skipped_by_status_filter() -> None:
    mgr = _StubManager()
    mgr.recorder.error(_flow_with_error())
    drv = _Driver(mgr)
    # No response, so status filter skips it.
    result = drv.browser_intercept_flows(status_code=200)
    assert result["flows"] == []
    # Without the filter the error entry is visible.
    result_all = drv.browser_intercept_flows()
    assert len(result_all["flows"]) == 1
    assert result_all["flows"][0]["error"] is not None
