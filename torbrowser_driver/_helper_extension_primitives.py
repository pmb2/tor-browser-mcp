"""Helper-extension capability surface.

Adds the observation primitives that ride the
:class:`~torbrowser_driver._helper_extension_bridge.HelperBridge`:
status, network capture lifecycle, and document-start init scripts.
Every tool method is tagged ``@capability("helper-extension")``.

The bridge plumbing (install, hello handshake, long-poll transport) is
owned by :mod:`_helper_extension_install` and :mod:`_helper_extension_bridge`;
this module is a thin driver-side adapter that drives the bridge and
assembles per-request envelopes from the event stream the extension
emits.
"""

from __future__ import annotations

import base64
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .capabilities import capability
from .exceptions import HelperUnavailable

if TYPE_CHECKING:
    from ._helper_extension_bridge import HelperBridge


_DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
_ALL_URLS = "<all_urls>"

# Firefox match-pattern syntax minus the URL-segment specifics the
# WebExtension parser cares about (querystring, fragment). We accept
# only the subset our tool surface actually documents.
_MATCH_PATTERN_RE = re.compile(
    r"^(?P<scheme>\*|https?|wss?|ftp|file)://"
    r"(?P<host>\*|\*\.[A-Za-z0-9.\-]+|[A-Za-z0-9.\-]+|)"
    r"(?P<path>/.*)$"
)


def validate_match_pattern(pattern: Any) -> str:
    """Return ``pattern`` unchanged when valid; otherwise raise ``ValueError``.

    Accepts the literal ``<all_urls>`` plus the documented
    ``<scheme>://<host><path>`` shapes (``*``, ``http``, ``https``,
    ``ws``, ``wss``, ``ftp``, ``file`` schemes; host may be ``*``,
    ``*.suffix``, a bare host, or empty for ``file://``; path starts
    with ``/``).
    """

    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"match pattern must be a non-empty string; got {pattern!r}")
    if pattern == _ALL_URLS:
        return pattern
    match = _MATCH_PATTERN_RE.match(pattern)
    if not match:
        raise ValueError(f"invalid match pattern: {pattern!r}")
    scheme = match.group("scheme")
    host = match.group("host")
    if scheme != "file" and host == "":
        raise ValueError(f"invalid match pattern: {pattern!r} (host required)")
    return pattern


def patterns_overlap(a: list[str], b: list[str]) -> bool:
    """Conservative overlap check between two pattern lists.

    Returns ``True`` when either side contains ``<all_urls>`` or any two
    entries are byte-equal. Precise pattern algebra is intentionally
    out of scope: the helper is meant to refuse obviously-overlapping
    captures, not to be a SAT solver over WebExtension match patterns.
    """

    if _ALL_URLS in a or _ALL_URLS in b:
        return True
    return any(x == y for x in a for y in b)


def decode_body(buf: bytes) -> str | dict[str, str]:
    """Return UTF-8 text when ``buf`` decodes cleanly; otherwise a
    ``{"base64": ...}`` envelope so the result remains JSON-safe."""

    try:
        return buf.decode("utf-8")
    except UnicodeDecodeError:
        return {"base64": base64.b64encode(buf).decode("ascii")}


def _now_ms() -> float:
    return time.time() * 1000.0


def _new_entry(request_id: str) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "method": None,
        "url": None,
        "request_headers": {},
        "request_body": None,
        "status_code": None,
        "response_headers": {},
        "response_body": None,
        "response_body_truncated": False,
        "started_at": None,
        "completed_at": None,
        "error": None,
        "ip": None,
    }


@dataclass
class _CaptureState:
    """In-flight capture buffer, keyed by ``capture_id``."""

    capture_id: str
    patterns: list[str]
    capture_response_body: bool
    max_body_bytes: int
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    body_buffers: dict[str, bytearray] = field(default_factory=dict)
    body_lengths: dict[str, int] = field(default_factory=dict)
    body_finalized: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)


def _ensure_entry(state: _CaptureState, request_id: str) -> dict[str, Any]:
    entry = state.entries.get(request_id)
    if entry is None:
        entry = _new_entry(request_id)
        state.entries[request_id] = entry
    return entry


def apply_request_observed(state: _CaptureState, data: dict[str, Any]) -> None:
    rid = str(data.get("request_id"))
    with state.lock:
        entry = _ensure_entry(state, rid)
        if data.get("method") is not None:
            entry["method"] = data["method"]
        if data.get("url") is not None:
            entry["url"] = data["url"]
        if data.get("started_at") is not None:
            entry["started_at"] = data["started_at"]


def apply_request_headers(state: _CaptureState, data: dict[str, Any]) -> None:
    rid = str(data.get("request_id"))
    headers = data.get("request_headers")
    if not isinstance(headers, dict):
        return
    with state.lock:
        entry = _ensure_entry(state, rid)
        entry["request_headers"] = dict(headers)


def apply_response_observed(state: _CaptureState, data: dict[str, Any]) -> None:
    rid = str(data.get("request_id"))
    with state.lock:
        entry = _ensure_entry(state, rid)
        if data.get("status_code") is not None:
            entry["status_code"] = data["status_code"]
        headers = data.get("response_headers")
        if isinstance(headers, dict):
            entry["response_headers"] = dict(headers)


def apply_body_chunk(state: _CaptureState, data: dict[str, Any]) -> None:
    rid = str(data.get("request_id"))
    chunk_b64 = data.get("chunk_b64") or ""
    is_final = bool(data.get("is_final"))
    with state.lock:
        entry = _ensure_entry(state, rid)
        buf = state.body_buffers.setdefault(rid, bytearray())
        current_len = state.body_lengths.get(rid, 0)
        buf_changed = False
        if chunk_b64:
            try:
                chunk = base64.b64decode(chunk_b64)
            except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
                chunk = b""
            allowed = state.max_body_bytes - current_len
            if allowed <= 0:
                if len(chunk) > 0:
                    entry["response_body_truncated"] = True
            elif len(chunk) > allowed:
                buf.extend(chunk[:allowed])
                state.body_lengths[rid] = current_len + allowed
                entry["response_body_truncated"] = True
                buf_changed = True
            else:
                buf.extend(chunk)
                state.body_lengths[rid] = current_len + len(chunk)
                buf_changed = True
        # The is_final marker may race ahead of in-flight chunks on the
        # JS side's HTTP pool; redecode whenever the buffer changes and
        # again on is_final so the final state is correct regardless of
        # arrival order.
        if buf_changed or is_final:
            entry["response_body"] = decode_body(bytes(buf))
        if is_final:
            state.body_finalized.add(rid)


def apply_response_completed(state: _CaptureState, data: dict[str, Any]) -> None:
    rid = str(data.get("request_id"))
    with state.lock:
        entry = _ensure_entry(state, rid)
        entry["completed_at"] = data.get("completed_at") or _now_ms()
        if "ip" in data:
            entry["ip"] = data.get("ip")


def apply_response_error(state: _CaptureState, data: dict[str, Any]) -> None:
    rid = str(data.get("request_id"))
    with state.lock:
        entry = _ensure_entry(state, rid)
        entry["error"] = data.get("error")
        if entry["completed_at"] is None:
            entry["completed_at"] = data.get("completed_at") or _now_ms()


def finalize_capture(state: _CaptureState) -> list[dict[str, Any]]:
    """Flush pending body buffers and return the entries list.

    Called by :meth:`browser_network_capture_stop` to materialise any
    request whose ``is_final`` body chunk never arrived (the response
    stream closed but the extension's ``onstop`` handler raced with
    capture removal).
    """

    with state.lock:
        for rid, buf in state.body_buffers.items():
            entry = state.entries.get(rid)
            if entry is None:
                continue
            if buf:
                entry["response_body"] = decode_body(bytes(buf))
                state.body_finalized.add(rid)
        return list(state.entries.values())


class _HelperExtensionCapabilityMixin:
    """Driver-side implementation of the ``helper-extension`` capability.

    Methods assume the bridge has been wired up in
    :meth:`TorBrowserDriver.__enter__`; absent or disconnected bridges
    raise :class:`HelperUnavailable` rather than crashing inside the
    bridge layer.
    """

    if TYPE_CHECKING:
        _helper_bridge: "HelperBridge | None"
        _helper_addon_id: str | None
        _helper_captures: dict[str, _CaptureState]
        _helper_init_scripts: set[str]
        _helper_subscribers_installed: bool

    def _helper_bridge_or_raise(self) -> "HelperBridge":
        bridge = getattr(self, "_helper_bridge", None)
        if bridge is None or not bridge.connected:
            raise HelperUnavailable(
                "helper-extension capability requires a connected bridge; "
                "enable the 'helper-extension' cap and ensure the install "
                "handshake succeeded"
            )
        return bridge

    def _captures_map(self) -> dict[str, _CaptureState]:
        captures = getattr(self, "_helper_captures", None)
        if captures is None:
            captures = {}
            self._helper_captures = captures
        return captures

    def _init_scripts_set(self) -> set[str]:
        scripts = getattr(self, "_helper_init_scripts", None)
        if scripts is None:
            scripts = set()
            self._helper_init_scripts = scripts
        return scripts

    def _ensure_event_subscribers(self, bridge: "HelperBridge") -> None:
        if getattr(self, "_helper_subscribers_installed", False):
            return
        bridge.subscribe("request.observed", self._on_request_observed)
        bridge.subscribe("request.headers", self._on_request_headers)
        bridge.subscribe("response.observed", self._on_response_observed)
        bridge.subscribe("body_chunk", self._on_body_chunk)
        bridge.subscribe("response.completed", self._on_response_completed)
        bridge.subscribe("response.error", self._on_response_error)
        self._helper_subscribers_installed = True

    def _route_event(self, data: dict[str, Any], apply_fn) -> None:
        capture_id = data.get("capture_id")
        if not isinstance(capture_id, str):
            return
        state = self._captures_map().get(capture_id)
        if state is None:
            return
        apply_fn(state, data)

    def _on_request_observed(self, data: dict[str, Any]) -> None:
        self._route_event(data, apply_request_observed)

    def _on_request_headers(self, data: dict[str, Any]) -> None:
        self._route_event(data, apply_request_headers)

    def _on_response_observed(self, data: dict[str, Any]) -> None:
        self._route_event(data, apply_response_observed)

    def _on_body_chunk(self, data: dict[str, Any]) -> None:
        self._route_event(data, apply_body_chunk)

    def _on_response_completed(self, data: dict[str, Any]) -> None:
        self._route_event(data, apply_response_completed)

    def _on_response_error(self, data: dict[str, Any]) -> None:
        self._route_event(data, apply_response_error)

    @capability("helper-extension")
    def browser_extension_status(self) -> dict[str, Any]:
        """Return a snapshot of the helper-extension's health.

        Always returns a dict; never raises. ``installed`` and
        ``bridge_connected`` are ``False`` when the bridge has not been
        constructed or has not completed the install-time handshake.
        Remaining fields are filled best-effort regardless.
        """

        bridge = getattr(self, "_helper_bridge", None)
        addon_id = getattr(self, "_helper_addon_id", None) or ""
        captures = self._captures_map()
        init_scripts = self._init_scripts_set()
        if bridge is None:
            return {
                "installed": False,
                "bridge_connected": False,
                "addon_id": addon_id,
                "bridge_host": "",
                "bridge_port": 0,
                "blocking_supported": True,
                "captures_active": len(captures),
                "init_scripts_registered": len(init_scripts),
            }
        connected = bool(bridge.connected)
        return {
            "installed": connected,
            "bridge_connected": connected,
            "addon_id": addon_id,
            "bridge_host": bridge.host,
            "bridge_port": bridge.port,
            "blocking_supported": True,
            "captures_active": len(captures),
            "init_scripts_registered": len(init_scripts),
        }

    @capability("helper-extension")
    def browser_network_capture_start(
        self,
        patterns: list[str] | None = None,
        capture_response_body: bool = True,
        max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
    ) -> dict[str, Any]:
        """Begin observing network traffic matching ``patterns``.

        Each pattern follows Firefox match-pattern syntax (see
        :func:`validate_match_pattern`). ``None`` is equivalent to
        ``["<all_urls>"]``. Per-response bodies are streamed via
        ``filterResponseData`` when ``capture_response_body`` is true and
        truncated at ``max_body_bytes`` bytes per response.

        Captures whose URL sets overlap an already-running capture are
        rejected with :class:`ValueError` to keep the per-request
        envelopes single-owner.
        """

        if patterns is None:
            normalized = [_ALL_URLS]
        else:
            if not isinstance(patterns, list) or not patterns:
                raise ValueError("patterns must be a non-empty list or None")
            normalized = [validate_match_pattern(p) for p in patterns]
        if not isinstance(max_body_bytes, int) or max_body_bytes < 0:
            raise ValueError("max_body_bytes must be a non-negative int")

        captures = self._captures_map()
        for cid, state in captures.items():
            if patterns_overlap(normalized, state.patterns):
                raise ValueError(
                    f"patterns {normalized!r} overlap with existing capture "
                    f"{cid!r} (patterns={state.patterns!r})"
                )

        bridge = self._helper_bridge_or_raise()
        self._ensure_event_subscribers(bridge)
        capture_id = secrets.token_hex(8)
        state = _CaptureState(
            capture_id=capture_id,
            patterns=normalized,
            capture_response_body=bool(capture_response_body),
            max_body_bytes=int(max_body_bytes),
        )
        captures[capture_id] = state
        try:
            bridge.request(
                "capture.start",
                {
                    "capture_id": capture_id,
                    "patterns": normalized,
                    "capture_response_body": bool(capture_response_body),
                    "max_body_bytes": int(max_body_bytes),
                },
            )
        except Exception:
            captures.pop(capture_id, None)
            raise
        return {"capture_id": capture_id}

    @capability("helper-extension")
    def browser_network_capture_stop(self, capture_id: str) -> dict[str, Any]:
        """Stop ``capture_id`` and return the assembled per-request envelopes.

        Raises :class:`ValueError` if ``capture_id`` is unknown. The
        extension-side listeners are removed before the entries are
        flushed; late events that arrive after stop are dropped on the
        floor (they hit ``_route_event`` with a missing capture).
        """

        captures = self._captures_map()
        state = captures.get(capture_id)
        if state is None:
            raise ValueError(f"unknown capture_id {capture_id!r}")

        bridge = self._helper_bridge_or_raise()
        try:
            bridge.request("capture.stop", {"capture_id": capture_id})
        finally:
            captures.pop(capture_id, None)
        entries = finalize_capture(state)
        return {"capture_id": capture_id, "entries": entries}

    @capability("helper-extension")
    def browser_add_init_script(self, source: str) -> dict[str, Any]:
        """Register a document-start content script across all frames.

        The extension wraps the supplied ``source`` in a
        ``browser.contentScripts.register`` call with
        ``runAt: "document_start"`` and ``matches: ["<all_urls>"]``. The
        returned ``script_id`` is the handle for
        :meth:`browser_remove_init_script`.
        """

        if not isinstance(source, str) or source == "":
            raise ValueError("source must be a non-empty string")
        bridge = self._helper_bridge_or_raise()
        script_id = secrets.token_hex(8)
        bridge.request(
            "init_script.register",
            {"script_id": script_id, "source": source},
        )
        self._init_scripts_set().add(script_id)
        return {"script_id": script_id}

    @capability("helper-extension")
    def browser_remove_init_script(self, script_id: str) -> dict[str, Any]:
        """Unregister an init script previously returned by
        :meth:`browser_add_init_script`.

        Raises :class:`ValueError` if ``script_id`` is unknown.
        """

        scripts = self._init_scripts_set()
        if script_id not in scripts:
            raise ValueError(f"unknown script_id {script_id!r}")
        bridge = self._helper_bridge_or_raise()
        bridge.request("init_script.unregister", {"script_id": script_id})
        scripts.discard(script_id)
        return {"removed": True}
