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


def _build_mock_data_url(
    status: int,
    content_type: str,
    body: str,
    headers: dict[str, str] | None,
) -> str:
    """Synthesise a ``data:`` URL suitable for an ``onBeforeRequest``
    ``redirectUrl`` return.

    Encodes ``body`` as base64 and produces
    ``data:<content_type>;base64,<payload>``. ``status`` and ``headers``
    are accepted for symmetry with the route entry but cannot be
    carried over a ``data:`` URL: Firefox treats the redirect target
    as a fresh request whose response status is ``200`` and whose only
    header is ``Content-Type`` parsed from the URL itself. Callers
    requiring arbitrary status codes or response headers should use
    the ``proxy-intercept`` capability.
    """

    payload = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return f"data:{content_type};base64,{payload}"


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
        surfaced instead to keep tool output bounded.
        """

        body_size = len(self.body.encode("utf-8")) if self.body is not None else None
        return {
            "route_id": self.route_id,
            "pattern": self.pattern,
            "mode": self.mode,
            "priority": self.priority,
            "status": self.status,
            "body_size": body_size,
            "content_type": self.content_type,
            "redirect_url": self.redirect_url,
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
        """Serialise the full route descriptor for the background page.

        The extension mirrors this descriptor in-process so its blocking
        listeners can evaluate routes without a bridge round-trip.
        """

        payload: dict[str, Any] = {
            "route_id": self.route_id,
            "pattern": self.pattern,
            "mode": self.mode,
            "priority": self.priority,
            "insertion_index": self.insertion_index,
        }
        if self.mode == "mock":
            payload["redirect_url"] = _build_mock_data_url(
                self.status if self.status is not None else 200,
                self.content_type or "text/plain",
                self.body or "",
                self.headers,
            )
        elif self.mode == "redirect":
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
        ``["<all_urls>"]``.

        The returned capture buffers per-request envelopes (URL, method,
        status code, request and response headers, peer IP, error
        string, started/completed timestamps) until
        :meth:`browser_network_capture_stop` is called.

        ``capture_response_body`` requests body streaming via
        ``webRequest.filterResponseData``. On Tor Browser 15.x / Firefox
        140 ESR the filter's ``ondata`` callback does not deliver bytes
        for matching responses, so the ``response_body`` field in each
        envelope is typically empty or ``None``; the rest of the
        envelope is populated as documented. Workflows that need actual
        response bytes should use the ``proxy-intercept`` capability,
        which sees wire traffic before the browser decrypts it.
        ``max_body_bytes`` caps any bytes that do arrive.

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
        headers, peer IP, error string, and started/completed
        timestamps. ``response_body`` is populated only when the
        platform actually delivers bytes through
        ``filterResponseData.ondata`` (see
        :meth:`browser_network_capture_start` for the TB 15.x caveat).

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
          requests by returning ``redirectUrl`` pointing at a
          synthesised ``data:`` URL carrying ``body`` and
          ``content_type``. A ``data:`` redirect cannot carry custom
          HTTP status or arbitrary response headers, so the supplied
          ``status`` and ``headers`` are recorded on the route entry for
          echo via :meth:`browser_route_list` but do not affect the
          response the page observes. On Tor Browser 15.x / Firefox 140
          ESR the ``data:``-URL redirect itself currently fails to
          deliver the synthesised body to page-context ``fetch()`` of
          subresources -- the call rejects with a network error even
          though the route is registered and evaluated. Workflows that
          need real response mocking, custom status codes, or arbitrary
          response headers should use the ``proxy-intercept``
          capability.
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
        route_id = secrets.token_hex(8)
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
            redirect_url=redirect_url if mode == "redirect" else None,
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
            bridge.request("route.remove", {"route_ids": [route_id]})
            return {"removed": 1}
        victims = [rid for rid, r in routes.items() if r.pattern == pattern]
        for rid in victims:
            routes.pop(rid, None)
        if victims:
            bridge.request("route.remove", {"route_ids": victims})
        return {"removed": len(victims)}

    @capability("helper-extension")
    def browser_route_list(self) -> list[dict[str, Any]]:
        """Return installed routes in evaluation order.

        Routes are sorted by ``priority`` (descending) with insertion
        order as the tiebreaker -- the order the blocking listeners use
        when picking the first matching rule.
        """

        return [entry.echo() for entry in self._ordered_routes()]

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
