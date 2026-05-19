"""HTTP long-poll bridge between the driver and the helper WebExtension.

The driver owns a stdlib HTTP/1.1 server bound to localhost. The
helper extension's background page is the only client; it dials in
once at install time with ``POST /hello`` (token-authenticated), then
long-polls ``GET /poll`` for driver-issued requests and posts
``POST /response`` for each one. Events flow the other way via
``POST /event``.

The transport is HTTP rather than WebSocket because WebSocket dials
from a WebExtension principal do not reach the localhost listener on
Tor Browser 15 / Firefox 140 ESR even with ``allow_hijacking_localhost``
and ``no_proxies_on`` set; ``fetch()`` from the same principal does.
"""

from __future__ import annotations

import hmac
import itertools
import json
import logging
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

from .exceptions import (
    HelperBridgeDisconnected,
    HelperBridgeTimeout,
    HelperExtensionError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

log = logging.getLogger(__name__)


_POLL_TIMEOUT_SECONDS = 25.0
_POLL_TICK_SECONDS = 0.5
_SILENCE_DISCONNECT_SECONDS = 60.0
_WATCHDOG_TICK_SECONDS = 5.0
_MAX_BODY_BYTES = 1 << 20

# Mock route_id shape: hex (uuid4) with optional dashes, at least 20
# characters of entropy. Anything shorter or carrying non-hex bytes
# is treated as a malformed path component and rejected with 404 so
# /mock/../etc/passwd and similar can't reach the lookup table.
_MOCK_ROUTE_ID_RE = re.compile(r"^[0-9a-f-]{20,}$")


@dataclass(frozen=True)
class MockEntry:
    """A single mock response registered against a route_id.

    Headers are caller-supplied verbatim; the bridge fills in
    ``Content-Type`` (``application/octet-stream``) and
    ``Content-Length`` only when the caller did not provide them. The
    body is already encoded -- registrations from the driver side pass
    bytes, never str.
    """

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


class _PendingRequest:
    """One outgoing request awaiting its matching response."""

    __slots__ = ("dead", "error", "event", "result")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: dict[str, Any] | None = None
        self.error: BaseException | None = None
        self.dead = False


class _Handler(BaseHTTPRequestHandler):
    """Dispatcher for the four bridge endpoints.

    The owning :class:`HelperBridge` is reachable via
    ``self.server.bridge`` (set by :class:`_Server`).
    """

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _bridge(self) -> HelperBridge:
        return self.server.bridge  # type: ignore[attr-defined]

    def _authenticate(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        provided = auth[len("Bearer ") :]
        return hmac.compare_digest(provided, self._bridge().token)

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_length)
        except ValueError:
            return b""
        if length <= 0 or length > _MAX_BODY_BYTES:
            return b""
        return self.rfile.read(length)

    def _drain_body(self) -> None:
        """Consume any pending request body before replying with an error.

        Without this, BaseHTTPRequestHandler closes the underlying socket
        while the client is still writing its body. On Windows the
        resulting RST surfaces in the client as WinError 10053.
        """

        raw_length = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_length)
        except ValueError:
            return
        if length <= 0:
            return
        remaining = min(length, _MAX_BODY_BYTES)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 4096))
            if not chunk:
                return
            remaining -= len(chunk)

    def _send(
        self,
        status: int,
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> None:
        self.send_response(status)
        if body is None or len(body) == 0:
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send(status, data, "application/json")

    def _parse_json_body(self) -> dict[str, Any] | None:
        body = self._read_body()
        if not body:
            return {}
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(decoded, dict):
            return None
        return decoded

    def do_POST(self) -> None:
        bridge = self._bridge()
        if bridge.is_closed:
            self._drain_body()
            self._send(503)
            return
        if not self._authenticate():
            self._drain_body()
            self._send(401)
            return
        path = self.path.split("?", 1)[0]
        if path not in ("/hello", "/response", "/event"):
            self._drain_body()
            self._send(404)
            return
        message = self._parse_json_body()
        if message is None:
            self._send(400)
            return
        if path == "/hello":
            bridge._handle_hello(message)
            self._send_json(200, {"ok": True, "session": bridge.token})
            return
        if path == "/response":
            bridge._handle_response(message)
            self._send(204)
            return
        bridge._handle_event(message)
        self._send(204)

    def do_GET(self) -> None:
        bridge = self._bridge()
        if bridge.is_closed:
            self._send(503)
            return
        path = self.path.split("?", 1)[0]
        if path.startswith("/mock/"):
            self._serve_mock(bridge, path)
            return
        if path == "/host":
            self._serve_host(bridge)
            return
        if not self._authenticate():
            self._send(401)
            return
        if path != "/poll":
            self._send(404)
            return
        item = bridge._wait_for_outgoing()
        if item is None:
            self._send(204)
            return
        self._send_json(200, item)

    def _serve_host(self, bridge: HelperBridge) -> None:
        """Serve a minimal HTML host page from the bridge origin.

        Mock-mode redirects target ``/mock/<route_id>`` on the bridge.
        For a page-context ``fetch()`` to follow a cross-origin redirect
        into the bridge origin, the originating page must itself be on
        an origin that Tor Browser permits cross-origin fetches from --
        ``data:`` URL documents do not qualify. Hosting a tiny page on
        the bridge origin lets tests (and consumers) navigate there
        first so the subsequent mock fetch terminates on a same-origin
        target. Like ``/mock``, this is intentionally unauthenticated:
        page principals cannot attach the bridge's bearer token.
        """

        body = (
            b"<!doctype html><html><head>"
            b"<meta charset=\"utf-8\">"
            b"<title>tor-browser-mcp helper host</title>"
            b"</head><body></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _serve_mock(self, bridge: HelperBridge, path: str) -> None:
        """Serve a registered mock body to page-context fetch.

        Intentionally unauthenticated: page JavaScript redirected here
        by ``webRequest.onBeforeRequest`` cannot attach the bridge's
        ``Authorization: Bearer`` header. The route_id is generated by
        the driver as ``uuid4().hex`` (128 bits of entropy) and the
        URL is therefore unguessable by random scanning; that is the
        access control for this endpoint.
        """

        route_id = path[len("/mock/") :]
        if not _MOCK_ROUTE_ID_RE.match(route_id):
            self._send(404)
            return
        entry = bridge._lookup_mock(route_id)
        if entry is None:
            self._send(404)
            return
        status = entry.status if isinstance(entry.status, int) else 200
        body = entry.body or b""
        headers = dict(entry.headers or {})
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/octet-stream"
        if not any(k.lower() == "content-length" for k in headers):
            headers["Content-Length"] = str(len(body))
        # Mock responses are reached via cross-origin redirects from
        # page-context fetch (the original request hits an arbitrary
        # host; the extension rewrites it to 127.0.0.1). Without an
        # Access-Control-Allow-Origin header the CORS check on the
        # redirect's final response fails and the fetch rejects.
        # Access-Control-Expose-Headers is the matching grant that
        # lets page JS read non-safelisted response headers via
        # ``response.headers.get(...)``. Caller-supplied values win;
        # the defaults are permissive wildcards.
        if not any(k.lower() == "access-control-allow-origin" for k in headers):
            headers["Access-Control-Allow-Origin"] = "*"
        if not any(k.lower() == "access-control-expose-headers" for k in headers):
            headers["Access-Control-Expose-Headers"] = "*"
        log.debug(
            "mock served route_id=%s status=%s bytes=%s",
            route_id,
            status,
            len(body),
        )
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, str(value))
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except OSError:
                pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        bridge: HelperBridge,
    ) -> None:
        super().__init__(address, handler)
        self.bridge = bridge


class HelperBridge:
    """HTTP long-poll bridge to the helper WebExtension.

    The bridge owns a localhost-bound HTTP listener on ``(host, port)``.
    Authentication is per-request via ``Authorization: Bearer <token>``.
    A single extension instance is expected; the bridge does not enforce
    single-client, but the on-the-wire shape (one ``/hello`` then a
    long-poll loop) presumes one.
    """

    def __init__(self, host: str, port: int, token: str) -> None:
        self._host = host
        self._port = port
        self._token = token

        self._server: _Server | None = None
        self._server_thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None

        self._state_lock = threading.Lock()
        self._closed = False
        self._connected = False
        self._last_seen: float = 0.0

        self._connect_event = threading.Event()
        self._shutdown_event = threading.Event()

        self._id_counter = itertools.count(1)
        self._pending: dict[int, _PendingRequest] = {}
        self._pending_lock = threading.Lock()

        self._outgoing: queue.Queue[dict[str, Any]] = queue.Queue()

        self._subscribers: dict[str, list[Callable[[dict[str, Any]], None]]] = {}
        self._subscribers_lock = threading.Lock()

        self._mocks: dict[str, MockEntry] = {}
        self._mocks_lock = threading.Lock()

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def token(self) -> str:
        return self._token

    @property
    def connected(self) -> bool:
        with self._state_lock:
            return self._connected

    @property
    def connect_event(self) -> threading.Event:
        """Event set once the extension has completed ``/hello``."""

        return self._connect_event

    @property
    def is_closed(self) -> bool:
        with self._state_lock:
            return self._closed

    def start(self) -> None:
        """Bind the HTTP listener and spawn the serve + watchdog threads."""

        if self._server is not None:
            raise HelperExtensionError("HelperBridge.start() called twice")
        self._server = _Server((self._host, self._port), _Handler, self)
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            name="helper-bridge-server",
            daemon=True,
        )
        self._server_thread.start()
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="helper-bridge-watchdog",
            daemon=True,
        )
        self._watchdog_thread.start()

    def close(self) -> None:
        """Tear down listener, unblock pending polls, fail pending requests."""

        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._connected = False

        self._shutdown_event.set()
        self._connect_event.set()

        server = self._server
        self._server = None
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass

        self._fail_pending("bridge closed")

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Enqueue a request, block until the extension responds.

        Demultiplexes by integer id; safe to call from multiple threads.
        Raises :class:`HelperBridgeDisconnected` if the bridge is closed
        or not yet connected, and :class:`HelperBridgeTimeout` if no
        response arrives within ``timeout`` seconds.
        """

        with self._state_lock:
            if self._closed:
                raise HelperBridgeDisconnected("bridge is closed")
            if not self._connected:
                raise HelperBridgeDisconnected("bridge is not connected")

        request_id = next(self._id_counter)
        pending = _PendingRequest()
        with self._pending_lock:
            self._pending[request_id] = pending

        frame = {"id": request_id, "method": method, "params": params or {}}
        self._outgoing.put(frame)

        signalled = pending.event.wait(timeout)
        with self._pending_lock:
            self._pending.pop(request_id, None)
        if not signalled:
            pending.dead = True
            raise HelperBridgeTimeout(
                f"helper request {method!r} did not return within {timeout:.1f}s"
            )
        if pending.error is not None:
            raise pending.error
        assert pending.result is not None
        return pending.result

    def subscribe(
        self,
        event_name: str,
        sink: Callable[[dict[str, Any]], None],
    ) -> None:
        """Register a sink for ``POST /event`` frames named ``event_name``."""

        with self._subscribers_lock:
            self._subscribers.setdefault(event_name, []).append(sink)

    def register_mock(
        self,
        route_id: str,
        status: int,
        headers: dict[str, str] | None,
        body: bytes,
    ) -> None:
        """Publish a mock response at ``/mock/<route_id>``.

        The HTTP handler reads this table without authentication; the
        route_id's entropy is the access control. Driver-side callers
        own the lifecycle and must call :meth:`unregister_mock` when
        the matching route goes away.
        """

        entry = MockEntry(
            status=int(status),
            headers=dict(headers or {}),
            body=bytes(body),
        )
        with self._mocks_lock:
            self._mocks[route_id] = entry

    def unregister_mock(self, route_id: str) -> None:
        """Drop the mock entry for ``route_id`` if present; otherwise no-op."""

        with self._mocks_lock:
            self._mocks.pop(route_id, None)

    def list_mocks(self) -> list[str]:
        """Return the route_ids of all registered mocks."""

        with self._mocks_lock:
            return list(self._mocks.keys())

    def _lookup_mock(self, route_id: str) -> MockEntry | None:
        with self._mocks_lock:
            return self._mocks.get(route_id)

    def _wait_for_outgoing(self) -> dict[str, Any] | None:
        """Block up to ``_POLL_TIMEOUT_SECONDS`` for the next outgoing request.

        Returns ``None`` if the poll budget elapsed or the bridge is
        shutting down; the handler turns that into a 204.
        """

        with self._state_lock:
            self._last_seen = time.monotonic()
        deadline = time.monotonic() + _POLL_TIMEOUT_SECONDS
        while True:
            if self._shutdown_event.is_set():
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            wait = min(_POLL_TICK_SECONDS, remaining)
            try:
                item = self._outgoing.get(timeout=wait)
            except queue.Empty:
                continue
            with self._state_lock:
                self._last_seen = time.monotonic()
            return item

    def _handle_hello(self, message: dict[str, Any]) -> None:
        with self._state_lock:
            self._connected = True
            self._last_seen = time.monotonic()
        self._connect_event.set()

    def _handle_response(self, message: dict[str, Any]) -> None:
        with self._state_lock:
            self._last_seen = time.monotonic()
        request_id = message.get("id")
        if not isinstance(request_id, int):
            return
        with self._pending_lock:
            pending = self._pending.get(request_id)
        if pending is None or pending.dead:
            return
        error = message.get("error")
        if error is not None:
            msg = "helper request failed"
            code: Any = None
            if isinstance(error, dict):
                msg = str(error.get("message") or msg)
                code = error.get("code")
            err = HelperExtensionError(msg)
            err.code = code  # type: ignore[attr-defined]
            pending.error = err
        else:
            result = message.get("result")
            pending.result = result if isinstance(result, dict) else {"value": result}
        pending.event.set()

    def _handle_event(self, message: dict[str, Any]) -> None:
        with self._state_lock:
            self._last_seen = time.monotonic()
        name = message.get("name")
        if not isinstance(name, str):
            return
        data = message.get("data")
        payload = data if isinstance(data, dict) else {"value": data}
        with self._subscribers_lock:
            sinks = list(self._subscribers.get(name, ()))
        for sink in sinks:
            try:
                sink(payload)
            except Exception:
                log.exception("helper bridge subscriber raised")

    def _watchdog_loop(self) -> None:
        while not self._shutdown_event.wait(_WATCHDOG_TICK_SECONDS):
            with self._state_lock:
                if not self._connected:
                    continue
                silence = time.monotonic() - self._last_seen
                if silence < _SILENCE_DISCONNECT_SECONDS:
                    continue
                self._connected = False
            self._connect_event.set()
            self._fail_pending(f"no traffic for {silence:.0f}s")

    def _fail_pending(self, reason: str) -> None:
        with self._pending_lock:
            entries = list(self._pending.values())
            self._pending.clear()
        for pending in entries:
            if pending.event.is_set():
                continue
            pending.error = HelperBridgeDisconnected(reason)
            pending.event.set()
