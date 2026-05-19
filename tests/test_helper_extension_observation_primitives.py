"""Unit tests for the helper-extension observation primitives.

These tests exercise the driver-side adapter
(:mod:`torbrowser_driver._helper_extension_primitives`) against a mock
bridge, plus the standalone match-pattern validator, overlap detector,
and per-request envelope assembly logic.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from torbrowser_driver._helper_extension_primitives import (
    _CaptureState,
    _HelperExtensionCapabilityMixin,
    _apply_page_body,
    _envelope_from_page_body,
    _match_page_body_to_envelope,
    _truncate_to_bytes,
    apply_body_chunk,
    apply_body_observed,
    apply_request_headers,
    apply_request_observed,
    apply_response_completed,
    apply_response_error,
    apply_response_observed,
    decode_body,
    finalize_capture,
    patterns_overlap,
    validate_match_pattern,
)
from torbrowser_driver.exceptions import HelperUnavailable


# --- mock plumbing ----------------------------------------------------------


class _FakeBridge:
    """Stand-in for :class:`HelperBridge` that records ``request`` calls.

    Subscribers are stored and invoked manually from tests so per-event
    assembly can be exercised deterministically.
    """

    def __init__(self, connected: bool = True, host: str = "127.0.0.1", port: int = 9999) -> None:
        self.connected = connected
        self.host = host
        self.port = port
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.results: dict[str, dict[str, Any]] = {}
        self.subscribers: dict[str, list[Any]] = {}

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0):
        self.calls.append((method, dict(params or {})))
        return self.results.get(method, {"ok": True})

    def subscribe(self, name: str, sink) -> None:
        self.subscribers.setdefault(name, []).append(sink)


class _Driver(_HelperExtensionCapabilityMixin):
    """Bare driver shell with just the helper-extension state slots."""

    def __init__(self, bridge: _FakeBridge | None) -> None:
        self._helper_bridge = bridge
        self._helper_addon_id = "helper@tor-browser-mcp.local"


# --- match-pattern validator ------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        "<all_urls>",
        "*://*.example.com/*",
        "https://example.com/path",
        "https://example.com/*",
        "http://*/*",
        "*://*/*",
        "ws://example.com/*",
        "wss://*.example.com/*",
        "file:///tmp/*",
    ],
)
def test_validate_match_pattern_accepts_valid(pattern: str) -> None:
    assert validate_match_pattern(pattern) == pattern


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        "*",
        "example.com/*",
        "https://example.com",
        "://example.com/*",
        "ftp:/example.com/*",
        "javascript:*",
        "https:///path",
        None,
        42,
    ],
)
def test_validate_match_pattern_rejects_invalid(pattern: Any) -> None:
    with pytest.raises(ValueError):
        validate_match_pattern(pattern)


# --- capture overlap --------------------------------------------------------


def test_patterns_overlap_two_all_urls() -> None:
    assert patterns_overlap(["<all_urls>"], ["<all_urls>"]) is True


def test_patterns_overlap_all_urls_versus_specific() -> None:
    assert patterns_overlap(["<all_urls>"], ["https://example.com/*"]) is True
    assert patterns_overlap(["https://example.com/*"], ["<all_urls>"]) is True


def test_patterns_overlap_equal_specific() -> None:
    assert patterns_overlap(
        ["https://example.com/*"], ["https://example.com/*"]
    ) is True


def test_patterns_overlap_disjoint_specific() -> None:
    assert patterns_overlap(
        ["https://a.example.com/*"], ["https://b.example.com/*"]
    ) is False


# --- body decoding ----------------------------------------------------------


def test_decode_body_utf8_returns_str() -> None:
    assert decode_body("hello world".encode("utf-8")) == "hello world"


def test_decode_body_non_utf8_returns_base64_envelope() -> None:
    raw = b"\xff\xfe\xfd\x00\x01"
    decoded = decode_body(raw)
    assert isinstance(decoded, dict)
    assert "base64" in decoded
    assert base64.b64decode(decoded["base64"]) == raw


# --- browser_extension_status -----------------------------------------------


def test_browser_extension_status_bridge_none() -> None:
    drv = _Driver(bridge=None)
    status = drv.browser_extension_status()
    assert status["installed"] is False
    assert status["bridge_connected"] is False
    assert status["captures_active"] == 0
    assert status["init_scripts_registered"] == 0
    assert status["blocking_supported"] is True


def test_browser_extension_status_bridge_disconnected_reports_false() -> None:
    bridge = _FakeBridge(connected=False, port=9258)
    drv = _Driver(bridge=bridge)
    status = drv.browser_extension_status()
    assert status["installed"] is False
    assert status["bridge_connected"] is False
    assert status["bridge_host"] == "127.0.0.1"
    assert status["bridge_port"] == 9258


def test_browser_extension_status_bridge_connected_reports_snapshot() -> None:
    bridge = _FakeBridge(connected=True, port=9258)
    drv = _Driver(bridge=bridge)
    status = drv.browser_extension_status()
    assert status["installed"] is True
    assert status["bridge_connected"] is True
    assert status["addon_id"] == "helper@tor-browser-mcp.local"
    assert status["bridge_host"] == "127.0.0.1"
    assert status["bridge_port"] == 9258
    assert status["blocking_supported"] is True
    assert status["captures_active"] == 0
    assert status["init_scripts_registered"] == 0


# --- capture start / stop round-trips --------------------------------------


def test_capture_start_calls_bridge_with_normalized_patterns() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    result = drv.browser_network_capture_start(
        patterns=["https://example.com/*"],
        capture_response_body=True,
        max_body_bytes=1024,
    )
    assert "capture_id" in result
    assert len(bridge.calls) == 1
    method, params = bridge.calls[0]
    assert method == "capture.start"
    assert params["patterns"] == ["https://example.com/*"]
    assert params["capture_response_body"] is True
    assert params["max_body_bytes"] == 1024
    assert params["capture_id"] == result["capture_id"]


def test_capture_start_defaults_to_all_urls_when_patterns_none() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv.browser_network_capture_start(patterns=None)
    _, params = bridge.calls[0]
    assert params["patterns"] == ["<all_urls>"]


def test_capture_start_rejects_overlapping_capture() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv.browser_network_capture_start(patterns=["<all_urls>"])
    with pytest.raises(ValueError, match="overlap"):
        drv.browser_network_capture_start(patterns=["https://example.com/*"])


def test_capture_start_raises_when_bridge_missing() -> None:
    drv = _Driver(bridge=None)
    with pytest.raises(HelperUnavailable):
        drv.browser_network_capture_start()


def test_capture_stop_unknown_id_raises() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    with pytest.raises(ValueError, match="unknown capture_id"):
        drv.browser_network_capture_stop("does-not-exist")


def test_capture_stop_round_trip_returns_entries() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    start = drv.browser_network_capture_start(patterns=["https://example.com/*"])
    capture_id = start["capture_id"]
    state = drv._captures_map()[capture_id]
    apply_request_observed(
        state,
        {
            "request_id": "r1",
            "method": "GET",
            "url": "https://example.com/",
            "started_at": 1.0,
        },
    )
    apply_response_observed(
        state,
        {
            "request_id": "r1",
            "status_code": 200,
            "response_headers": {"Content-Type": "text/html"},
        },
    )
    apply_body_chunk(
        state,
        {
            "request_id": "r1",
            "chunk_b64": base64.b64encode(b"hi").decode("ascii"),
            "is_final": True,
        },
    )

    result = drv.browser_network_capture_stop(capture_id)

    assert result["capture_id"] == capture_id
    assert len(result["entries"]) == 1
    entry = result["entries"][0]
    assert entry["request_id"] == "r1"
    assert entry["method"] == "GET"
    assert entry["url"] == "https://example.com/"
    assert entry["status_code"] == 200
    assert entry["response_body"] == "hi"
    assert entry["response_body_truncated"] is False
    assert entry["source"] == "webrequest"

    methods = [m for m, _ in bridge.calls]
    assert methods == ["capture.start", "capture.stop"]
    assert capture_id not in drv._captures_map()


# --- page-world body merge -------------------------------------------------


def _page_body(
    *,
    url: str,
    method: str = "GET",
    body: str = "",
    status: int = 200,
    headers: dict[str, str] | None = None,
    page_id: str = "",
    truncated: bool = False,
    observed_at: float | None = None,
) -> dict[str, Any]:
    return {
        "page_id": page_id,
        "url": url,
        "method": method.upper(),
        "status_code": status,
        "response_headers": dict(headers or {}),
        "response_body": body,
        "response_body_truncated": truncated,
        "observed_at": observed_at,
    }


def test_match_page_body_to_envelope_exact_match() -> None:
    envelope = {"method": "GET", "url": "https://example.com/api"}
    pending = [_page_body(url="https://example.com/api", method="GET", body="a")]
    match = _match_page_body_to_envelope(envelope, pending)
    assert match is not None
    assert match["response_body"] == "a"


def test_match_page_body_to_envelope_url_mismatch_returns_none() -> None:
    envelope = {"method": "GET", "url": "https://example.com/a"}
    pending = [_page_body(url="https://example.com/b")]
    assert _match_page_body_to_envelope(envelope, pending) is None


def test_match_page_body_to_envelope_method_mismatch_returns_none() -> None:
    envelope = {"method": "POST", "url": "https://example.com/api"}
    pending = [_page_body(url="https://example.com/api", method="GET")]
    assert _match_page_body_to_envelope(envelope, pending) is None


def test_match_page_body_to_envelope_fifo_on_same_pair() -> None:
    envelope = {"method": "GET", "url": "https://example.com/api"}
    pending = [
        _page_body(url="https://example.com/api", body="first"),
        _page_body(url="https://example.com/api", body="second"),
    ]
    match = _match_page_body_to_envelope(envelope, pending)
    assert match is not None
    assert match["response_body"] == "first"


def test_apply_page_body_sets_response_and_source_merged() -> None:
    envelope = {
        "method": "GET",
        "url": "https://example.com/api",
        "response_body": None,
        "response_body_truncated": False,
        "source": "webrequest",
        "page_id": None,
    }
    pb = _page_body(url="https://example.com/api", body="hello", page_id="tbm-f-1")
    _apply_page_body(envelope, pb, max_body_bytes=1024)
    assert envelope["response_body"] == "hello"
    assert envelope["response_body_truncated"] is False
    assert envelope["source"] == "merged"
    assert envelope["page_id"] == "tbm-f-1"


def test_apply_page_body_clips_to_max_body_bytes() -> None:
    envelope = {
        "method": "GET",
        "url": "https://example.com/api",
        "response_body": None,
        "response_body_truncated": False,
        "source": "webrequest",
        "page_id": None,
    }
    pb = _page_body(url="https://example.com/api", body="abcdef")
    _apply_page_body(envelope, pb, max_body_bytes=3)
    assert envelope["response_body"] == "abc"
    assert envelope["response_body_truncated"] is True
    assert envelope["source"] == "merged"


def test_apply_page_body_preserves_page_side_truncation_flag() -> None:
    envelope = {
        "method": "GET",
        "url": "https://example.com/api",
        "response_body": None,
        "response_body_truncated": False,
        "source": "webrequest",
        "page_id": None,
    }
    pb = _page_body(url="https://example.com/api", body="ok", truncated=True)
    _apply_page_body(envelope, pb, max_body_bytes=1024)
    assert envelope["response_body"] == "ok"
    assert envelope["response_body_truncated"] is True


def test_truncate_to_bytes_snaps_to_utf8_boundary() -> None:
    # 'e\u0301' (e + combining acute) is 3 UTF-8 bytes (e=1 + accent=2).
    text = "a\u00e9b"  # a + e-acute + b = 1 + 2 + 1 = 4 bytes
    clipped, truncated = _truncate_to_bytes(text, 2)
    assert truncated is True
    assert clipped == "a"
    assert clipped.encode("utf-8") == b"a"


def test_truncate_to_bytes_no_clip_for_fitting_text() -> None:
    clipped, truncated = _truncate_to_bytes("hello", 1024)
    assert clipped == "hello"
    assert truncated is False


def test_finalize_capture_merges_page_body_into_webrequest_envelope() -> None:
    state = _make_state()
    apply_request_observed(
        state,
        {
            "request_id": "r1",
            "method": "GET",
            "url": "https://example.com/api",
        },
    )
    apply_response_observed(
        state,
        {
            "request_id": "r1",
            "status_code": 200,
            "response_headers": {"Content-Type": "application/json"},
        },
    )
    apply_body_observed(
        state,
        {
            "url": "https://example.com/api",
            "method": "GET",
            "status_code": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"ok": true}',
            "page_id": "tbm-f-1",
        },
    )
    entries = finalize_capture(state)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["request_id"] == "r1"
    assert entry["response_body"] == '{"ok": true}'
    assert entry["source"] == "merged"
    assert entry["page_id"] == "tbm-f-1"
    # webRequest-side fields stay populated.
    assert entry["status_code"] == 200
    assert entry["response_headers"] == {"Content-Type": "application/json"}


def test_finalize_capture_page_only_request_becomes_synthetic_envelope() -> None:
    state = _make_state()
    apply_body_observed(
        state,
        {
            "url": "https://example.com/sw-only",
            "method": "POST",
            "status_code": 201,
            "response_headers": {"Content-Type": "text/plain"},
            "response_body": "made-by-service-worker",
            "page_id": "tbm-x-7",
            "observed_at": 1234.5,
        },
    )
    entries = finalize_capture(state)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["request_id"] is None
    assert entry["method"] == "POST"
    assert entry["url"] == "https://example.com/sw-only"
    assert entry["status_code"] == 201
    assert entry["response_body"] == "made-by-service-worker"
    assert entry["source"] == "page"
    assert entry["page_id"] == "tbm-x-7"
    assert entry["completed_at"] == 1234.5


def test_finalize_capture_webrequest_only_entry_keeps_source_webrequest() -> None:
    state = _make_state()
    apply_request_observed(
        state,
        {
            "request_id": "r9",
            "method": "GET",
            "url": "https://cdn.example.com/img.png",
        },
    )
    apply_response_observed(
        state,
        {
            "request_id": "r9",
            "status_code": 200,
            "response_headers": {"Content-Type": "image/png"},
        },
    )
    entries = finalize_capture(state)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["source"] == "webrequest"
    assert entry["response_body"] is None


def test_finalize_capture_truncates_page_body_to_max_bytes() -> None:
    state = _make_state(max_body_bytes=4)
    apply_request_observed(
        state,
        {
            "request_id": "r1",
            "method": "GET",
            "url": "https://example.com/api",
        },
    )
    apply_body_observed(
        state,
        {
            "url": "https://example.com/api",
            "method": "GET",
            "response_body": "abcdefgh",
        },
    )
    entries = finalize_capture(state)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["response_body"] == "abcd"
    assert entry["response_body_truncated"] is True
    assert entry["source"] == "merged"


def test_finalize_capture_two_parallel_requests_pair_fifo() -> None:
    state = _make_state()
    apply_request_observed(
        state,
        {"request_id": "r1", "method": "GET", "url": "https://example.com/api"},
    )
    apply_request_observed(
        state,
        {"request_id": "r2", "method": "GET", "url": "https://example.com/api"},
    )
    apply_body_observed(
        state,
        {"url": "https://example.com/api", "method": "GET", "response_body": "first"},
    )
    apply_body_observed(
        state,
        {"url": "https://example.com/api", "method": "GET", "response_body": "second"},
    )
    entries = finalize_capture(state)
    assert len(entries) == 2
    r1 = next(e for e in entries if e["request_id"] == "r1")
    r2 = next(e for e in entries if e["request_id"] == "r2")
    assert r1["response_body"] == "first"
    assert r2["response_body"] == "second"
    assert r1["source"] == "merged"
    assert r2["source"] == "merged"


def test_envelope_from_page_body_marks_source_page_and_request_id_none() -> None:
    pb = _page_body(
        url="https://example.com/x",
        method="PUT",
        body="data",
        status=204,
        headers={"Content-Type": "text/plain"},
        page_id="tbm-f-42",
        observed_at=99.0,
    )
    entry = _envelope_from_page_body(pb, max_body_bytes=1024)
    assert entry["request_id"] is None
    assert entry["source"] == "page"
    assert entry["page_id"] == "tbm-f-42"
    assert entry["method"] == "PUT"
    assert entry["url"] == "https://example.com/x"
    assert entry["status_code"] == 204
    assert entry["response_headers"] == {"Content-Type": "text/plain"}
    assert entry["response_body"] == "data"
    assert entry["completed_at"] == 99.0


def test_capture_stop_subscribes_body_observed_event() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    drv.browser_network_capture_start(patterns=["https://example.com/*"])
    assert "body.observed" in bridge.subscribers


# --- per-request envelope assembly -----------------------------------------


def _make_state(max_body_bytes: int = 1024) -> _CaptureState:
    return _CaptureState(
        capture_id="cap",
        patterns=["<all_urls>"],
        capture_response_body=True,
        max_body_bytes=max_body_bytes,
    )


def test_envelope_assembly_fills_every_field() -> None:
    state = _make_state()
    apply_request_observed(
        state,
        {
            "request_id": "rid",
            "method": "POST",
            "url": "https://example.com/path",
            "started_at": 123.0,
        },
    )
    apply_request_headers(
        state,
        {"request_id": "rid", "request_headers": {"Accept": "*/*"}},
    )
    apply_response_observed(
        state,
        {
            "request_id": "rid",
            "status_code": 201,
            "response_headers": {"Content-Type": "application/json"},
        },
    )
    apply_body_chunk(
        state,
        {
            "request_id": "rid",
            "chunk_b64": base64.b64encode(b'{"ok": true}').decode("ascii"),
            "is_final": True,
        },
    )
    apply_response_completed(
        state,
        {"request_id": "rid", "completed_at": 200.0, "ip": "203.0.113.5"},
    )

    entries = finalize_capture(state)
    assert len(entries) == 1
    e = entries[0]
    assert e["request_id"] == "rid"
    assert e["method"] == "POST"
    assert e["url"] == "https://example.com/path"
    assert e["started_at"] == 123.0
    assert e["request_headers"] == {"Accept": "*/*"}
    assert e["status_code"] == 201
    assert e["response_headers"] == {"Content-Type": "application/json"}
    assert e["response_body"] == '{"ok": true}'
    assert e["response_body_truncated"] is False
    assert e["completed_at"] == 200.0
    assert e["ip"] == "203.0.113.5"
    assert e["error"] is None
    assert e["request_body"] is None


def test_response_error_records_error_field() -> None:
    state = _make_state()
    apply_request_observed(state, {"request_id": "r", "method": "GET", "url": "x"})
    apply_response_error(
        state,
        {"request_id": "r", "error": "net::ERR_FAILED", "completed_at": 9.0},
    )
    entries = finalize_capture(state)
    assert entries[0]["error"] == "net::ERR_FAILED"
    assert entries[0]["completed_at"] == 9.0


def test_body_truncation_marks_truncated_and_clips_to_max() -> None:
    state = _make_state(max_body_bytes=4)
    apply_request_observed(state, {"request_id": "r", "method": "GET", "url": "x"})
    apply_body_chunk(
        state,
        {
            "request_id": "r",
            "chunk_b64": base64.b64encode(b"AB").decode("ascii"),
            "is_final": False,
        },
    )
    apply_body_chunk(
        state,
        {
            "request_id": "r",
            "chunk_b64": base64.b64encode(b"CDEF").decode("ascii"),
            "is_final": False,
        },
    )
    apply_body_chunk(
        state,
        {
            "request_id": "r",
            "chunk_b64": base64.b64encode(b"GH").decode("ascii"),
            "is_final": True,
        },
    )

    entries = finalize_capture(state)
    assert entries[0]["response_body_truncated"] is True
    assert entries[0]["response_body"] == "ABCD"


def test_body_decoding_non_utf8_returns_base64_envelope() -> None:
    state = _make_state()
    apply_request_observed(state, {"request_id": "r", "method": "GET", "url": "x"})
    raw = b"\xff\xfe\x00\x01"
    apply_body_chunk(
        state,
        {
            "request_id": "r",
            "chunk_b64": base64.b64encode(raw).decode("ascii"),
            "is_final": True,
        },
    )
    body = finalize_capture(state)[0]["response_body"]
    assert isinstance(body, dict)
    assert base64.b64decode(body["base64"]) == raw


def test_finalize_capture_assembles_body_when_no_final_chunk_arrived() -> None:
    state = _make_state()
    apply_request_observed(state, {"request_id": "r", "method": "GET", "url": "x"})
    apply_body_chunk(
        state,
        {
            "request_id": "r",
            "chunk_b64": base64.b64encode(b"partial").decode("ascii"),
            "is_final": False,
        },
    )
    entries = finalize_capture(state)
    assert entries[0]["response_body"] == "partial"


# --- init scripts -----------------------------------------------------------


def test_add_init_script_rejects_empty_source() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="source must be a non-empty string"):
        drv.browser_add_init_script("")


def test_add_init_script_rejects_non_string() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="source must be a non-empty string"):
        drv.browser_add_init_script(None)  # type: ignore[arg-type]


def test_add_init_script_round_trip() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    result = drv.browser_add_init_script("window.__t = 1;")
    assert "script_id" in result
    method, params = bridge.calls[0]
    assert method == "init_script.register"
    assert params["script_id"] == result["script_id"]
    assert params["source"] == "window.__t = 1;"
    assert result["script_id"] in drv._init_scripts_set()


def test_remove_init_script_round_trip() -> None:
    bridge = _FakeBridge()
    drv = _Driver(bridge=bridge)
    sid = drv.browser_add_init_script("window.__t = 1;")["script_id"]
    bridge.calls.clear()
    result = drv.browser_remove_init_script(sid)
    assert result == {"removed": True}
    assert sid not in drv._init_scripts_set()
    method, params = bridge.calls[0]
    assert method == "init_script.unregister"
    assert params["script_id"] == sid


def test_remove_init_script_unknown_id_raises() -> None:
    drv = _Driver(bridge=_FakeBridge())
    with pytest.raises(ValueError, match="unknown script_id"):
        drv.browser_remove_init_script("nope")


def test_add_init_script_raises_when_bridge_missing() -> None:
    drv = _Driver(bridge=None)
    with pytest.raises(HelperUnavailable):
        drv.browser_add_init_script("window.x = 1;")
