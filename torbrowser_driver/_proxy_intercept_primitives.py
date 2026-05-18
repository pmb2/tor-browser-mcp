"""Proxy-intercept capability surface.

Rides on top of :class:`~torbrowser_driver._proxy_intercept_substrate.ProxyManager`
and exposes five observation tools tagged ``@capability("proxy-intercept")``:
status (``browser_intercept_start``), teardown of the recorder buffer
(``browser_intercept_stop``), bulk listing (``browser_intercept_flows``),
single-flow lookup (``browser_intercept_flow``), and persistence to a
mitmproxy-native flow archive (``browser_intercept_save``).

The substrate itself is started in :meth:`TorBrowserDriver.__enter__` and
torn down on close; the ``start``/``stop`` tools here drive only the
recorder's bounded buffer, not the daemon thread or the upstream tor
SOCKS chain. ``browser_intercept_save`` routes its output path through
:class:`~torbrowser_driver.path_policy.PathPolicy.resolve_output`.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from .capabilities import capability
from .exceptions import ProxyInterceptError

if TYPE_CHECKING:
    from ._proxy_intercept_substrate import ProxyManager
    from .config import DriverConfig


_DEFAULT_FLOWS_BODY_LIMIT = 1 * 1024 * 1024
_DEFAULT_FLOW_BODY_LIMIT = 5 * 1024 * 1024
_DEFAULT_FLOWS_RESULT_LIMIT = 200


def _decode_body(buf: bytes, max_body_bytes: int) -> tuple[Any, bool]:
    """Return ``(body, truncated)`` for ``buf`` capped at ``max_body_bytes``.

    UTF-8-decodable bytes are returned as ``str``; otherwise a
    ``{"base64": ...}`` envelope keeps the result JSON-safe.
    """

    truncated = False
    payload = buf
    if max_body_bytes >= 0 and len(buf) > max_body_bytes:
        payload = buf[:max_body_bytes]
        truncated = True
    try:
        return payload.decode("utf-8"), truncated
    except UnicodeDecodeError:
        return (
            {"base64": base64.b64encode(payload).decode("ascii")},
            truncated,
        )


def _safe_content(message: Any) -> bytes | None:
    """Return decoded message body, falling back to raw bytes on failure.

    mitmproxy's ``get_content(strict=False)`` decodes ``content-encoding``
    (gzip / brotli / deflate / zstd) without raising on malformed payloads;
    ``raw_content`` is the on-the-wire bytes and is the right fallback when
    ``get_content`` itself blows up on a partial or non-message body.
    """

    if message is None:
        return None
    try:
        data = message.get_content(strict=False)
        if data is not None:
            return data
    except Exception:  # noqa: BLE001
        pass
    return getattr(message, "raw_content", None)


def _augment_request(entry_request: dict, raw_flow: Any, include_bodies: bool,
                     max_body_bytes: int) -> dict:
    """Return a request dict enriched with body or truncation markers."""

    out = dict(entry_request)
    body_bytes: bytes | None = None
    if raw_flow is not None:
        body_bytes = _safe_content(getattr(raw_flow, "request", None))
    has_body = bool(body_bytes)
    if include_bodies:
        if has_body:
            decoded, truncated = _decode_body(body_bytes, max_body_bytes)
            out["body"] = decoded
            if truncated:
                out["request_body_truncated"] = True
        else:
            out["body"] = None
    else:
        out["request_body_truncated"] = has_body
    return out


def _augment_response(entry_response: dict | None, raw_flow: Any,
                      include_bodies: bool, max_body_bytes: int) -> dict | None:
    """Return a response dict enriched with body or truncation markers."""

    if entry_response is None:
        return None
    out = dict(entry_response)
    body_bytes: bytes | None = None
    if raw_flow is not None:
        body_bytes = _safe_content(getattr(raw_flow, "response", None))
    has_body = bool(body_bytes)
    if include_bodies:
        if has_body:
            decoded, truncated = _decode_body(body_bytes, max_body_bytes)
            out["body"] = decoded
            if truncated:
                out["response_body_truncated"] = True
        else:
            out["body"] = None
    else:
        out["response_body_truncated"] = has_body
    return out


def _materialise_entry(entry: dict, raw_flow: Any, include_bodies: bool,
                       max_body_bytes: int) -> dict:
    """Build the tool-facing dict for one buffer entry plus its raw flow."""

    out = dict(entry)
    req = entry.get("request")
    if isinstance(req, dict):
        out["request"] = _augment_request(req, raw_flow, include_bodies, max_body_bytes)
    resp = entry.get("response")
    out["response"] = _augment_response(resp, raw_flow, include_bodies, max_body_bytes)
    return out


class _ProxyInterceptCapabilityMixin:
    """Driver-side implementation of the ``proxy-intercept`` capability.

    Substrate boot is owned by :meth:`TorBrowserDriver.__enter__`; this
    mixin's tools only operate against the already-running
    :class:`ProxyManager` recorder buffer. Each tool calls
    :meth:`_proxy_alive_check` first so a dead or absent substrate
    surfaces as :class:`ProxyInterceptError`.
    """

    if TYPE_CHECKING:
        _proxy_manager: "ProxyManager | None"
        _proxy_ca_fingerprint: str | None
        config: "DriverConfig"

    def _proxy_alive_check(self) -> None:
        mgr = getattr(self, "_proxy_manager", None)
        if mgr is None:
            raise ProxyInterceptError(
                "proxy-intercept capability not enabled"
            )
        if not mgr.is_alive():
            err = mgr.last_error()
            if err is not None:
                raise ProxyInterceptError(
                    f"proxy-intercept substrate is down: {err!r}"
                )
            raise ProxyInterceptError(
                "proxy-intercept substrate is down"
            )

    @capability("proxy-intercept")
    def browser_intercept_start(self) -> dict[str, Any]:
        """Confirm the intercept substrate is up and return a tail cursor.

        The substrate itself is started in
        :meth:`TorBrowserDriver.__enter__`; this tool returns the
        current monotonic ``since`` cursor so callers can pass it back
        to :meth:`browser_intercept_flows` to tail new entries. The
        recorder buffer is not cleared here -- a fresh tail is
        achieved by passing the returned cursor on the next
        ``browser_intercept_flows`` call.

        Returns ``{"started": True, "intercept_port": int,
        "ca_fingerprint": str, "since": int}``.

        Raises :class:`ProxyInterceptError` if the substrate is not
        running.
        """

        self._proxy_alive_check()
        mgr = self._proxy_manager
        assert mgr is not None
        fingerprint = getattr(self, "_proxy_ca_fingerprint", None) or ""
        return {
            "started": True,
            "intercept_port": mgr.listen_port,
            "ca_fingerprint": fingerprint,
            "since": mgr.next_since,
        }

    @capability("proxy-intercept")
    def browser_intercept_stop(self) -> dict[str, Any]:
        """Stop the recorder: empty the buffer and reset the cursor.

        Does **not** shut down the daemon thread or the upstream tor
        SOCKS chain; the proxy lives for the driver session. A
        subsequent :meth:`browser_intercept_start` is fine and returns
        the now-zero cursor.

        Returns ``{"stopped": True, "flows_collected": int}`` -- the
        count is the buffer size at the moment of the clear.
        """

        self._proxy_alive_check()
        mgr = self._proxy_manager
        assert mgr is not None
        evicted = mgr.clear_buffer()
        return {"stopped": True, "flows_collected": evicted}

    @capability("proxy-intercept")
    def browser_intercept_flows(
        self,
        since: int | None = None,
        host: str | None = None,
        status_code: int | None = None,
        limit: int = _DEFAULT_FLOWS_RESULT_LIMIT,
        include_bodies: bool = False,
        max_body_bytes: int = _DEFAULT_FLOWS_BODY_LIMIT,
    ) -> dict[str, Any]:
        """List recorded flows with optional filtering.

        Filters are applied in order: ``since`` (only entries with
        monotonic index strictly greater than ``since``), ``host``
        (case-insensitive substring match against
        ``request.host``), ``status_code`` (exact match against
        ``response.status_code``; skips flows with no response).

        ``limit`` caps the number of returned entries; ``truncated`` is
        ``True`` when more entries matched than were returned.

        ``include_bodies=False`` (default) returns each entry without
        bodies but with ``request_body_truncated`` /
        ``response_body_truncated`` booleans indicating whether a body
        existed. ``include_bodies=True`` inlines bodies, each capped
        at ``max_body_bytes``; UTF-8-decodable bodies come back as
        ``str``, others as ``{"base64": ...}``.

        Returns ``{"flows": [...], "next_since": int, "truncated": bool}``.
        ``next_since`` is the largest ``since`` value across the
        returned entries (or the input ``since`` when no entries
        matched).
        """

        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError("limit must be a non-negative int")
        if not isinstance(max_body_bytes, int) or max_body_bytes < 0:
            raise ValueError("max_body_bytes must be a non-negative int")
        if since is not None and (
            isinstance(since, bool) or not isinstance(since, int)
        ):
            raise ValueError("since must be an int or None")
        if host is not None and not isinstance(host, str):
            raise ValueError("host must be a string or None")
        if status_code is not None and (
            isinstance(status_code, bool) or not isinstance(status_code, int)
        ):
            raise ValueError("status_code must be an int or None")

        self._proxy_alive_check()
        mgr = self._proxy_manager
        assert mgr is not None

        host_needle = host.lower() if host is not None else None
        snapshot = list(mgr.flow_buffer)

        matches: list[dict] = []
        for entry in snapshot:
            entry_since = entry.get("since")
            if since is not None and isinstance(entry_since, int):
                if entry_since <= since:
                    continue
            req = entry.get("request") if isinstance(entry.get("request"), dict) else None
            if host_needle is not None:
                req_host = (req or {}).get("host") if req else None
                if not isinstance(req_host, str):
                    continue
                if host_needle not in req_host.lower():
                    continue
            if status_code is not None:
                resp = entry.get("response")
                if not isinstance(resp, dict):
                    continue
                if resp.get("status_code") != status_code:
                    continue
            matches.append(entry)

        truncated = len(matches) > limit
        selected = matches[:limit] if limit > 0 else matches[:0]

        result_entries: list[dict] = []
        next_since = since if isinstance(since, int) else -1
        for entry in selected:
            raw = mgr.flow_by_id(entry.get("id", ""))
            result_entries.append(
                _materialise_entry(entry, raw, include_bodies, max_body_bytes)
            )
            es = entry.get("since")
            if isinstance(es, int) and es > next_since:
                next_since = es

        if next_since < 0:
            next_since = 0
        return {
            "flows": result_entries,
            "next_since": next_since,
            "truncated": truncated,
        }

    @capability("proxy-intercept")
    def browser_intercept_flow(
        self,
        flow_id: str,
        include_bodies: bool = True,
        max_body_bytes: int = _DEFAULT_FLOW_BODY_LIMIT,
    ) -> dict[str, Any]:
        """Return one flow by its mitmproxy-assigned ``flow.id``.

        Defaults to ``include_bodies=True`` so the typical
        "give me everything about this one flow" call gets the body.
        ``max_body_bytes`` caps each body the same way
        :meth:`browser_intercept_flows` does.

        Raises :class:`ValueError` if ``flow_id`` is not in the
        current buffer (the entry may have been evicted past
        ``max_flows`` or never recorded).
        """

        if not isinstance(flow_id, str) or not flow_id:
            raise ValueError("flow_id must be a non-empty string")
        if not isinstance(max_body_bytes, int) or max_body_bytes < 0:
            raise ValueError("max_body_bytes must be a non-negative int")

        self._proxy_alive_check()
        mgr = self._proxy_manager
        assert mgr is not None

        for entry in mgr.flow_buffer:
            if entry.get("id") == flow_id:
                raw = mgr.flow_by_id(flow_id)
                return _materialise_entry(entry, raw, include_bodies, max_body_bytes)
        raise ValueError(f"unknown flow_id {flow_id!r}")

    @capability("proxy-intercept")
    def browser_intercept_save(self, path: str) -> dict[str, Any]:
        """Persist the current buffer to a mitmproxy-native flow archive.

        ``path`` is resolved through
        :meth:`PathPolicy.resolve_output`. The file format is the
        ``mitmproxy.io.FlowWriter`` stream the ``mitmweb`` /
        ``mitmproxy`` console tooling consumes. Synthetic entries
        without a raw flow (e.g. ``tls_failed_client`` records) are
        skipped; only real captured ``HTTPFlow`` objects land in the
        archive.

        Returns ``{"path": str, "flow_count": int}`` -- the resolved
        absolute path plus the count of flows actually written.
        """

        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")

        self._proxy_alive_check()
        mgr = self._proxy_manager
        assert mgr is not None

        from mitmproxy import io as mitm_io

        resolved = self.config.path_policy.resolve_output(path)
        raw_flows = mgr.raw_flows_snapshot()

        with open(resolved, "wb") as fh:
            writer = mitm_io.FlowWriter(fh)
            for flow in raw_flows:
                writer.add(flow)

        return {
            "path": str(resolved),
            "flow_count": len(raw_flows),
        }
