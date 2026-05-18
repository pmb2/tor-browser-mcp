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
import itertools
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

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


def _new_entry(request_id: str | None) -> dict[str, Any]:
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
        "source": "webrequest",
        "page_id": None,
    }


_ROUTE_MODES = ("mock", "redirect", "headers")


@dataclass
class _RouteEntry:
    """One installed route in driver-side evaluation order.

    ``insertion_index`` is the tiebreaker when two routes share a
    ``priority``: the earlier insertion wins.
    """

    route_id: str
    pattern: str
    mode: str
    priority: int
    insertion_index: int
    status: int | None = None
    body: str | None = None
    content_type: str | None = None
    headers: dict[str, str] | None = None
    redirect_url: str | None = None
    set_request_headers: dict[str, str] | None = None
    remove_request_headers: list[str] | None = None
    set_response_headers: dict[str, str] | None = None
    remove_response_headers: list[str] | None = None

    def echo(self) -> dict[str, Any]:
        """Render as a JSON-safe descriptor for ``browser_route_list``.

        Mock-mode bodies are not echoed verbatim; ``body_size`` is
        surfaced instead to keep tool output bounded. ``redirect_url``
        on a mock entry is omitted -- the driver-internal value points
        at the bridge's localhost ``/mock/<id>`` URL, which is an
        implementation detail callers should not see.
        """

        body_size = len(self.body.encode("utf-8")) if self.body is not None else None
        echoed_redirect = self.redirect_url if self.mode == "redirect" else None
        return {
            "route_id": self.route_id,
            "pattern": self.pattern,
            "mode": self.mode,
            "priority": self.priority,
            "status": self.status,
            "body_size": body_size,
            "content_type": self.content_type,
            "headers": dict(self.headers) if self.headers else None,
            "redirect_url": echoed_redirect,
            "set_request_headers": (
                dict(self.set_request_headers) if self.set_request_headers else None
            ),
            "remove_request_headers": (
                list(self.remove_request_headers) if self.remove_request_headers else None
            ),
            "set_response_headers": (
                dict(self.set_response_headers) if self.set_response_headers else None
            ),
            "remove_response_headers": (
                list(self.remove_response_headers) if self.remove_response_headers else None
            ),
        }

    def to_extension_payload(self) -> dict[str, Any]:
        """Serialise the route descriptor for the background page.

        The extension only ever sees three concrete shapes: redirect,
        header-rewrite, and offline. Mock-mode routes are projected
        into ``"redirect"`` mode pointing at the bridge's ``/mock/<id>``
        endpoint -- the bridge serves the mock body over HTTP from
        localhost, which is reachable from page context and not
        subject to the ``data:``-URL deliverability gap that affects
        Firefox 140 ESR. The driver-side ``mode`` field stays
        ``"mock"`` for echo purposes only.
        """

        if self.mode == "mock":
            extension_mode = "redirect"
        else:
            extension_mode = self.mode
        payload: dict[str, Any] = {
            "route_id": self.route_id,
            "pattern": self.pattern,
            "mode": extension_mode,
            "priority": self.priority,
            "insertion_index": self.insertion_index,
        }
        if self.mode in ("mock", "redirect"):
            payload["redirect_url"] = self.redirect_url
        else:
            payload["set_request_headers"] = (
                dict(self.set_request_headers) if self.set_request_headers else {}
            )
            payload["remove_request_headers"] = list(self.remove_request_headers or [])
            payload["set_response_headers"] = (
                dict(self.set_response_headers) if self.set_response_headers else {}
            )
            payload["remove_response_headers"] = list(self.remove_response_headers or [])
        return payload


def _resolve_route_mode(
    body: str | None,
    redirect_url: str | None,
    set_request_headers: dict[str, str] | None,
    remove_request_headers: list[str] | None,
    set_response_headers: dict[str, str] | None,
    remove_response_headers: list[str] | None,
) -> str:
    """Pick the route mode from the supplied arguments.

    Exactly one of (mock body, redirect URL, header rewrite) must be
    set; otherwise the caller has expressed an ambiguous route and we
    raise :class:`ValueError`.
    """

    has_mock = body is not None
    has_redirect = redirect_url is not None
    has_headers = bool(
        set_request_headers
        or remove_request_headers
        or set_response_headers
        or remove_response_headers
    )
    count = int(has_mock) + int(has_redirect) + int(has_headers)
    if count == 0:
        raise ValueError(
            "browser_route requires one of: body (mock), redirect_url, or"
            " a header-rewrite argument"
        )
    if count > 1:
        raise ValueError(
            "browser_route modes are mutually exclusive: pick one of body"
            " (mock), redirect_url, or a header-rewrite argument"
        )
    if has_mock:
        return "mock"
    if has_redirect:
        return "redirect"
    return "headers"


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
    page_pending: list[dict[str, Any]] = field(default_factory=list)
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


def apply_body_observed(state: _CaptureState, data: dict[str, Any]) -> None:
    """Buffer a page-world body envelope for later merge into the capture.

    The webRequest event stream and the page-world override use distinct
    id namespaces, so the merge cannot happen on arrival; it is deferred
    to :func:`finalize_capture`, which pairs entries by ``(method, url)``
    and falls back to synthetic envelopes for page-only requests.
    """

    url = data.get("url")
    if not isinstance(url, str) or not url:
        return
    method = data.get("method")
    method_norm = method.upper() if isinstance(method, str) and method else "GET"
    headers = data.get("response_headers")
    headers_dict = dict(headers) if isinstance(headers, dict) else {}
    body = data.get("response_body")
    body_str = body if isinstance(body, str) else ""
    page_body = {
        "page_id": str(data.get("page_id") or ""),
        "url": url,
        "method": method_norm,
        "status_code": data.get("status_code"),
        "response_headers": headers_dict,
        "response_body": body_str,
        "response_body_truncated": bool(data.get("response_body_truncated")),
        "observed_at": data.get("observed_at"),
    }
    with state.lock:
        state.page_pending.append(page_body)


def _truncate_to_bytes(text: str, max_bytes: int) -> tuple[str, bool]:
    """Clip ``text`` so its UTF-8 encoding fits inside ``max_bytes``.

    Returns ``(clipped_text, truncated)``. Truncation snaps to a UTF-8
    character boundary so the resulting string is always valid UTF-8.
    """

    if max_bytes < 0:
        max_bytes = 0
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    clipped = encoded[:max_bytes]
    return clipped.decode("utf-8", errors="ignore"), True


def _match_page_body_to_envelope(
    envelope: dict[str, Any],
    pending: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Find the oldest pending page-world body whose ``(method, url)``
    matches ``envelope``; return it without removing from ``pending``.

    Returns ``None`` when no candidate fits. ``method`` comparison is
    case-insensitive; ``url`` comparison is exact-string. The caller is
    responsible for popping the matched entry once it commits to using
    it -- this keeps the matcher pure and the FIFO-by-method-and-url
    semantics testable without mutating shared state.
    """

    target_url = envelope.get("url")
    target_method = envelope.get("method")
    if not isinstance(target_url, str) or not target_url:
        return None
    target_method_norm = (
        target_method.upper() if isinstance(target_method, str) and target_method else None
    )
    for candidate in pending:
        if candidate.get("url") != target_url:
            continue
        cand_method = candidate.get("method")
        cand_method_norm = (
            cand_method.upper() if isinstance(cand_method, str) and cand_method else None
        )
        if target_method_norm is not None and cand_method_norm is not None:
            if target_method_norm != cand_method_norm:
                continue
        return candidate
    return None


def _apply_page_body(
    envelope: dict[str, Any],
    page_body: dict[str, Any],
    max_body_bytes: int,
) -> None:
    """Fold a page-world body into a webRequest-side envelope in place.

    Sets ``response_body`` (UTF-8-truncated to ``max_body_bytes``),
    ``response_body_truncated`` (true when either the page side already
    flagged it or this call clipped further), ``page_id``, and flips
    ``source`` to ``"merged"``. Existing webRequest-side fields (URL,
    method, headers, status, IP, timestamps) are preserved.
    """

    body = page_body.get("response_body")
    if not isinstance(body, str):
        body = ""
    clipped, clipped_truncated = _truncate_to_bytes(body, max_body_bytes)
    envelope["response_body"] = clipped
    envelope["response_body_truncated"] = (
        bool(page_body.get("response_body_truncated")) or clipped_truncated
    )
    page_id = page_body.get("page_id")
    if isinstance(page_id, str) and page_id:
        envelope["page_id"] = page_id
    envelope["source"] = "merged"


def _envelope_from_page_body(
    page_body: dict[str, Any], max_body_bytes: int
) -> dict[str, Any]:
    """Build a synthetic envelope for a page-world request that webRequest
    never produced an entry for.

    Marks ``source="page"`` and leaves ``request_id`` ``None`` so callers
    can distinguish merged envelopes from page-only entries.
    """

    entry = _new_entry(None)
    entry["url"] = page_body.get("url")
    method = page_body.get("method")
    entry["method"] = method.upper() if isinstance(method, str) and method else "GET"
    status = page_body.get("status_code")
    entry["status_code"] = status if isinstance(status, int) else None
    headers = page_body.get("response_headers")
    if isinstance(headers, dict):
        entry["response_headers"] = dict(headers)
    body = page_body.get("response_body")
    if not isinstance(body, str):
        body = ""
    clipped, clipped_truncated = _truncate_to_bytes(body, max_body_bytes)
    entry["response_body"] = clipped
    entry["response_body_truncated"] = (
        bool(page_body.get("response_body_truncated")) or clipped_truncated
    )
    page_id = page_body.get("page_id")
    if isinstance(page_id, str) and page_id:
        entry["page_id"] = page_id
    observed_at = page_body.get("observed_at")
    if isinstance(observed_at, (int, float)):
        entry["completed_at"] = float(observed_at)
    entry["source"] = "page"
    return entry


def finalize_capture(state: _CaptureState) -> list[dict[str, Any]]:
    """Flush pending body buffers, merge page-world bodies, and return
    the assembled entries.

    Called by :meth:`browser_network_capture_stop`. Behaves in three
    stages:

    1. Flush any webRequest body chunks that never received a final
       marker -- the on-the-wire stream closed but the extension's
       ``onstop`` handler raced with capture removal.
    2. For each webRequest envelope whose ``response_body`` is empty,
       pop the oldest matching ``(method, url)`` page-world body and
       merge it in. Envelopes that already carry a body (an unlikely
       happy path on TB 15.x but the future-proof shape) keep their
       webRequest body and stay ``source="webrequest"``.
    3. Any remaining page-world bodies surface as synthetic
       ``source="page"`` envelopes so service-worker- and other
       webRequest-invisible requests do not vanish.
    """

    max_bytes = state.max_body_bytes
    with state.lock:
        for rid, buf in state.body_buffers.items():
            entry = state.entries.get(rid)
            if entry is None:
                continue
            if buf:
                entry["response_body"] = decode_body(bytes(buf))
                state.body_finalized.add(rid)

        ordered_envelopes = list(state.entries.values())
        for envelope in ordered_envelopes:
            if envelope.get("source") is None:
                envelope["source"] = "webrequest"
            existing_body = envelope.get("response_body")
            already_has_body = (
                isinstance(existing_body, str) and existing_body != ""
            ) or isinstance(existing_body, dict)
            if already_has_body:
                continue
            match = _match_page_body_to_envelope(envelope, state.page_pending)
            if match is None:
                continue
            state.page_pending.remove(match)
            _apply_page_body(envelope, match, max_bytes)

        synthesised = [
            _envelope_from_page_body(pb, max_bytes) for pb in state.page_pending
        ]
        state.page_pending.clear()
        return ordered_envelopes + synthesised


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
        _helper_routes: dict[str, _RouteEntry]
        _helper_route_counter: "itertools.count[int]"
        _helper_network_state: str

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

    def _routes_map(self) -> dict[str, _RouteEntry]:
        routes = getattr(self, "_helper_routes", None)
        if routes is None:
            routes = {}
            self._helper_routes = routes
        return routes

    def _route_counter(self) -> "itertools.count[int]":
        counter = getattr(self, "_helper_route_counter", None)
        if counter is None:
            counter = itertools.count()
            self._helper_route_counter = counter
        return counter

    def _ordered_routes(self) -> list[_RouteEntry]:
        return sorted(
            self._routes_map().values(),
            key=lambda r: (-r.priority, r.insertion_index),
        )

    def _register_mock_on_bridge(
        self,
        route_id: str,
        status: int,
        body: str | bytes,
        content_type: str | None,
        headers: dict[str, str] | None,
    ) -> str:
        """Publish a mock entry on the bridge and return its URL.

        The bridge serves ``/mock/<route_id>`` unauthenticated; the
        route_id's entropy is the access control. The returned URL is
        what the extension is told to redirect matching requests to.
        """

        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = bytes(body)
        headers_out: dict[str, str] = dict(headers or {})
        if content_type and not any(
            k.lower() == "content-type" for k in headers_out
        ):
            headers_out["Content-Type"] = content_type
        bridge = self._helper_bridge_or_raise()
        bridge.register_mock(route_id, int(status), headers_out, body_bytes)
        return f"http://{bridge.host}:{bridge.port}/mock/{route_id}"

    def _ensure_event_subscribers(self, bridge: "HelperBridge") -> None:
        if getattr(self, "_helper_subscribers_installed", False):
            return
        bridge.subscribe("request.observed", self._on_request_observed)
        bridge.subscribe("request.headers", self._on_request_headers)
        bridge.subscribe("response.observed", self._on_response_observed)
        bridge.subscribe("body_chunk", self._on_body_chunk)
        bridge.subscribe("response.completed", self._on_response_completed)
        bridge.subscribe("response.error", self._on_response_error)
        bridge.subscribe("body.observed", self._on_body_observed)
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

    def _on_body_observed(self, data: dict[str, Any]) -> None:
        self._route_event(data, apply_body_observed)

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
        ``["<all_urls>"]``.

        The returned capture buffers per-request envelopes (URL, method,
        status code, request and response headers, peer IP, error
        string, started/completed timestamps) until
        :meth:`browser_network_capture_stop` is called.

        ``capture_response_body`` requests response-body capture. Two
        sources feed it. ``webRequest.filterResponseData`` provides the
        envelope shell (URL, method, status, headers, peer IP, timing)
        for every matching request, plus body bytes on platforms where
        ``ondata`` delivers them; on Tor Browser 15.x / Firefox 140 ESR
        that callback fires but does not deliver payload bytes. A
        page-world ``fetch`` and ``XMLHttpRequest`` override, installed
        via a document-start content script, fills the gap for
        JS-initiated requests -- the realistic majority of body-bearing
        traffic. Bodies coming from the page world land in the same
        envelope as the matching webRequest entry (by ``(method, url)``
        with FIFO disambiguation between parallel requests to the same
        URL); fully page-only requests surface as their own entries
        with ``request_id = None`` and ``source = "page"``.
        ``max_body_bytes`` clips both sources -- byte-precise on
        UTF-8 boundaries for the page-world side.

        Each envelope carries a ``source`` field describing where its
        body came from: ``"webrequest"`` (envelope only, no body, or
        body from ``filterResponseData``), ``"merged"`` (webRequest
        envelope plus a matched page-world body), or ``"page"``
        (page-world only; no webRequest counterpart, common for
        service-worker-fronted requests). Subresource loads triggered
        by the document parser -- ``<img>`` ``src``, ``<link>``
        ``href``, ``<script>`` ``src`` -- never reach the page-world
        override and stay ``source = "webrequest"`` with empty
        ``response_body``; ``proxy-intercept`` is the substrate for
        wire-level body capture regardless of how the request was
        initiated.

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

        Returns ``{"capture_id": str, "entries": list[dict]}``. Each
        entry carries URL, method, status code, request and response
        headers, peer IP, error string, started/completed timestamps,
        ``response_body``, ``response_body_truncated``, ``source``
        (``"webrequest"`` / ``"merged"`` / ``"page"``), and ``page_id``
        when the body came from the page-world override. Page-world
        bodies are merged into the matching webRequest envelope by
        ``(method, url)``; unmatched page-world bodies surface as
        synthetic ``source="page"`` entries with ``request_id=None``.
        See :meth:`browser_network_capture_start` for which traffic
        each source covers.

        Raises :class:`ValueError` if ``capture_id`` is unknown. The
        extension-side listeners are removed before the entries are
        flushed; late events that arrive after stop are dropped on the
        floor.
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

    @capability("helper-extension")
    def browser_route(
        self,
        pattern: str,
        *,
        status: int = 200,
        body: str | None = None,
        content_type: str = "text/plain",
        headers: dict[str, str] | None = None,
        redirect_url: str | None = None,
        set_request_headers: dict[str, str] | None = None,
        remove_request_headers: list[str] | None = None,
        set_response_headers: dict[str, str] | None = None,
        remove_response_headers: list[str] | None = None,
        priority: int | None = None,
    ) -> dict[str, Any]:
        """Install a routing rule against ``pattern``.

        Modes are mutually exclusive; exactly one must be selected:

        * **Mock** -- ``body`` is set. The extension answers matching
          requests by returning ``redirectUrl`` pointing at the
          driver-side bridge's localhost ``/mock/<route_id>`` endpoint,
          which serves ``body`` with the supplied ``status``,
          ``content_type``, and ``headers``. Arbitrary status codes
          and response headers are supported; the page observes the
          response as if the origin had returned it. The mock body
          travels over loopback, never through tor, and never reaches
          ``proxy-intercept``'s flow buffer -- mocks are local-only.
          ``proxy-intercept`` is only needed for mocking traffic the
          helper extension cannot see (document-parser subresources,
          WebSocket frames).
        * **Redirect** -- ``redirect_url`` is set. The blocking
          ``onBeforeRequest`` listener returns ``{redirectUrl: ...}``.
          Works end-to-end against ``http(s)://`` targets.
        * **Header rewrite** -- any of ``set_request_headers``,
          ``remove_request_headers``, ``set_response_headers``,
          ``remove_response_headers`` is set. Implemented via
          ``onBeforeSendHeaders`` (request side) and
          ``onHeadersReceived`` (response side); the request and
          response bodies pass through untouched.

        ``priority`` orders routes during evaluation: higher first,
        insertion order as tiebreaker. ``None`` is treated as ``0``.
        Returns ``{"route_id": str}`` -- the handle for
        :meth:`browser_unroute`.
        """

        validate_match_pattern(pattern)
        mode = _resolve_route_mode(
            body,
            redirect_url,
            set_request_headers,
            remove_request_headers,
            set_response_headers,
            remove_response_headers,
        )
        if priority is None:
            resolved_priority = 0
        elif isinstance(priority, bool) or not isinstance(priority, int):
            raise ValueError("priority must be an int or None")
        else:
            resolved_priority = priority
        if mode == "mock":
            if not isinstance(status, int) or isinstance(status, bool):
                raise ValueError("status must be an int")
            if not isinstance(content_type, str) or not content_type:
                raise ValueError("content_type must be a non-empty string")
            if not isinstance(body, str):
                raise ValueError("body must be a string in mock mode")
        elif mode == "redirect":
            if not isinstance(redirect_url, str) or not redirect_url:
                raise ValueError("redirect_url must be a non-empty string")

        bridge = self._helper_bridge_or_raise()
        route_id = uuid.uuid4().hex
        bridge_redirect_url: str | None = None
        if mode == "mock":
            assert isinstance(body, str)
            bridge_redirect_url = self._register_mock_on_bridge(
                route_id, status, body, content_type, headers
            )
        entry = _RouteEntry(
            route_id=route_id,
            pattern=pattern,
            mode=mode,
            priority=resolved_priority,
            insertion_index=next(self._route_counter()),
            status=status if mode == "mock" else None,
            body=body if mode == "mock" else None,
            content_type=content_type if mode == "mock" else None,
            headers=(dict(headers) if headers and mode == "mock" else None),
            redirect_url=(
                bridge_redirect_url if mode == "mock"
                else (redirect_url if mode == "redirect" else None)
            ),
            set_request_headers=(
                dict(set_request_headers) if set_request_headers else None
            ),
            remove_request_headers=(
                list(remove_request_headers) if remove_request_headers else None
            ),
            set_response_headers=(
                dict(set_response_headers) if set_response_headers else None
            ),
            remove_response_headers=(
                list(remove_response_headers) if remove_response_headers else None
            ),
        )
        routes = self._routes_map()
        routes[route_id] = entry
        try:
            bridge.request("route.add", entry.to_extension_payload())
        except Exception:
            routes.pop(route_id, None)
            if mode == "mock":
                bridge.unregister_mock(route_id)
            raise
        return {"route_id": route_id}

    @capability("helper-extension")
    def browser_unroute(
        self,
        route_id: str | None = None,
        pattern: str | None = None,
    ) -> dict[str, Any]:
        """Remove one or more installed routes.

        Exactly one of ``route_id`` or ``pattern`` must be supplied; the
        former removes a single route, the latter removes every route
        whose pattern matches ``pattern`` byte-for-byte. Returns
        ``{"removed": int}`` with the count of routes actually dropped.
        """

        if (route_id is None) == (pattern is None):
            raise ValueError(
                "browser_unroute requires exactly one of route_id or pattern"
            )
        bridge = self._helper_bridge_or_raise()
        routes = self._routes_map()
        if route_id is not None:
            entry = routes.pop(route_id, None)
            if entry is None:
                return {"removed": 0}
            if entry.mode == "mock":
                bridge.unregister_mock(route_id)
            bridge.request("route.remove", {"route_ids": [route_id]})
            return {"removed": 1}
        victims = [rid for rid, r in routes.items() if r.pattern == pattern]
        victim_modes = [routes[rid].mode for rid in victims]
        for rid in victims:
            routes.pop(rid, None)
        for rid, victim_mode in zip(victims, victim_modes):
            if victim_mode == "mock":
                bridge.unregister_mock(rid)
        if victims:
            bridge.request("route.remove", {"route_ids": victims})
        return {"removed": len(victims)}

    @capability("helper-extension")
    def browser_route_list(self) -> dict[str, Any]:
        """Return installed routes in evaluation order.

        Routes are sorted by ``priority`` (descending) with insertion
        order as the tiebreaker -- the order the blocking listeners use
        when picking the first matching rule. Returns ``{"routes":
        [...]}`` where each entry is the JSON-safe descriptor produced
        by :meth:`_RouteEntry.echo`.
        """

        return {"routes": [entry.echo() for entry in self._ordered_routes()]}

    @capability("helper-extension")
    def browser_network_state_set(
        self,
        state: Literal["online", "offline"],
    ) -> dict[str, Any]:
        """Toggle the simulated network state.

        When ``state`` is ``"offline"`` the extension installs a
        blocking ``webRequest.onBeforeRequest`` listener that returns
        ``{cancel: true}`` for every URL, blocking new request
        initiation. In-flight requests already past ``onBeforeRequest``
        are not aborted and continue to completion. The extension's
        own long-poll traffic to the driver-side bridge is exempted so
        the transition back to ``"online"`` can be delivered.
        Transitioning to ``"online"`` removes the cancel listener.
        ``navigator.onLine`` is not toggled; pages that gate retries on
        that signal will not observe the offline state.
        """

        if state not in ("online", "offline"):
            raise ValueError(
                f"state must be 'online' or 'offline'; got {state!r}"
            )
        bridge = self._helper_bridge_or_raise()
        bridge.request("network_state.set", {"state": state})
        self._helper_network_state = state
        return {"state": state}
