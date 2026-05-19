"""Proxy-intercept capability surface.

Rides on top of :class:`~torbrowser_driver._proxy_intercept_substrate.ProxyManager`
and exposes six tools tagged ``@capability("proxy-intercept")``:
status (``browser_intercept_start``), teardown of the recorder buffer
(``browser_intercept_stop``), bulk listing (``browser_intercept_flows``),
single-flow lookup (``browser_intercept_flow``), persistence to a
mitmproxy-native flow archive (``browser_intercept_save``), and
client-replay of a captured flow with optional modifications
(``browser_intercept_replay``).

The substrate itself is started in :meth:`TorBrowserDriver.__enter__` and
torn down on close; the ``start``/``stop`` tools here drive only the
recorder's bounded buffer, not the daemon thread or the upstream tor
SOCKS chain. ``browser_intercept_save`` routes its output path through
:class:`~torbrowser_driver.path_policy.PathPolicy.resolve_output`.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

from ._primitive_helpers import _validate_limit
from .capabilities import capability
from .exceptions import ProxyInterceptError

if TYPE_CHECKING:
    from ._proxy_intercept_substrate import ProxyManager
    from .config import DriverConfig


_DEFAULT_FLOWS_BODY_LIMIT = 1 * 1024 * 1024
_DEFAULT_FLOW_BODY_LIMIT = 5 * 1024 * 1024
_DEFAULT_FLOWS_RESULT_LIMIT = 200
_DEFAULT_REPLAY_TIMEOUT = 30.0

ProxyHttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
ProxyHttpVersion = Literal["HTTP/1.0", "HTTP/1.1", "HTTP/2.0"]

_ALLOWED_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)
_ALLOWED_HTTP_VERSIONS = frozenset({"HTTP/1.0", "HTTP/1.1", "HTTP/2.0"})
_REPLAY_MODIFICATION_KEYS = frozenset(
    {
        "method",
        "url",
        "http_version",
        "set_request_headers",
        "remove_request_headers",
        "body",
        "body_base64",
    }
)


def _apply_replay_modifications(flow: Any, **modifications: Any) -> None:
    """Mutate ``flow.request`` in place according to ``modifications``.

    The accepted keys are:

    - ``method``: replaces ``flow.request.method``; the value must be
      one of the standard HTTP verbs (case-insensitive on input,
      uppercased before assignment).
    - ``url``: parsed with :func:`urllib.parse.urlparse`; must carry
      both a scheme and a host. Assigned via the ``Request.url``
      setter so host / path / scheme update together.
    - ``http_version``: replaces ``flow.request.http_version``; must be
      one of ``HTTP/1.0``, ``HTTP/1.1``, ``HTTP/2.0``.
    - ``set_request_headers``: case-insensitive merge into
      ``flow.request.headers``. mitmproxy's ``Headers`` container
      already treats names case-insensitively, so assigning
      ``headers[name] = value`` replaces any existing entry of the
      same name.
    - ``remove_request_headers``: case-insensitive removal; missing
      names are ignored.
    - ``body`` / ``body_base64``: mutually exclusive request body
      replacement. ``body`` is UTF-8 encoded; ``body_base64`` is
      base64-decoded. When neither is supplied, the source body
      survives unchanged.

    Unknown keys raise :class:`ValueError`. The caller is expected to
    have deep-copied the source flow before calling this helper; the
    function does not copy on the caller's behalf.
    """

    unknown = set(modifications) - _REPLAY_MODIFICATION_KEYS
    if unknown:
        raise ValueError(
            f"unknown replay modification keys: {sorted(unknown)!r}"
        )

    body = modifications.get("body")
    body_base64 = modifications.get("body_base64")
    if body is not None and body_base64 is not None:
        raise ValueError(
            "body and body_base64 are mutually exclusive"
        )

    method = modifications.get("method")
    if method is not None:
        if not isinstance(method, str) or not method:
            raise ValueError("method must be a non-empty string")
        normalised = method.upper()
        if normalised not in _ALLOWED_HTTP_METHODS:
            raise ValueError(
                f"method {method!r} is not one of {sorted(_ALLOWED_HTTP_METHODS)!r}"
            )
        flow.request.method = normalised

    url = modifications.get("url")
    if url is not None:
        if not isinstance(url, str) or not url:
            raise ValueError("url must be a non-empty string")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                f"url {url!r} must be an absolute http(s) URL with a host"
            )
        flow.request.url = url

    http_version = modifications.get("http_version")
    if http_version is not None:
        if (
            not isinstance(http_version, str)
            or http_version not in _ALLOWED_HTTP_VERSIONS
        ):
            raise ValueError(
                f"http_version {http_version!r} is not one of"
                f" {sorted(_ALLOWED_HTTP_VERSIONS)!r}"
            )
        flow.request.http_version = http_version

    set_headers = modifications.get("set_request_headers")
    if set_headers is not None:
        if not isinstance(set_headers, dict):
            raise ValueError(
                "set_request_headers must be a dict of name -> value"
            )
        for name, value in set_headers.items():
            if not isinstance(name, str) or not name:
                raise ValueError(
                    f"set_request_headers key must be a non-empty string;"
                    f" got {name!r}"
                )
            if not isinstance(value, str):
                raise ValueError(
                    f"set_request_headers value for {name!r} must be a string"
                )
            flow.request.headers[name] = value

    remove_headers = modifications.get("remove_request_headers")
    if remove_headers is not None:
        if not isinstance(remove_headers, (list, tuple)):
            raise ValueError(
                "remove_request_headers must be a list of header names"
            )
        for name in remove_headers:
            if not isinstance(name, str) or not name:
                raise ValueError(
                    f"remove_request_headers entry must be a non-empty"
                    f" string; got {name!r}"
                )
            try:
                del flow.request.headers[name]
            except KeyError:
                pass

    if body is not None:
        if not isinstance(body, str):
            raise ValueError("body must be a string")
        flow.request.content = body.encode("utf-8")
    elif body_base64 is not None:
        if not isinstance(body_base64, str):
            raise ValueError("body_base64 must be a string")
        try:
            decoded = base64.b64decode(body_base64, validate=True)
        except Exception as exc:
            raise ValueError(f"body_base64 is not valid base64: {exc}") from exc
        flow.request.content = decoded


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
    except Exception:
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
        _proxy_manager: ProxyManager | None
        _proxy_ca_fingerprint: str | None
        config: DriverConfig

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
        ``since`` value that the next captured flow will be assigned,
        so callers can pass it back to :meth:`browser_intercept_flows`
        to tail new entries. The recorder buffer is not cleared here
        -- a fresh tail is achieved by passing the returned cursor on
        the next ``browser_intercept_flows`` call.

        Cursor semantics: ``since`` is an **inclusive** lower bound.
        ``browser_intercept_flows(since=N)`` returns all entries whose
        ``flow.since`` is ``>= N``. The value returned here is the
        ``flow.since`` that the *next* captured flow will receive, so
        ``browser_intercept_flows(since=<value-returned-by-start>)``
        returns exactly the flows captured after this call. On a fresh
        buffer the returned cursor is ``0``.

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
        limit: int | None = _DEFAULT_FLOWS_RESULT_LIMIT,
        include_bodies: bool = False,
        max_body_bytes: int = _DEFAULT_FLOWS_BODY_LIMIT,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """List recorded flows with optional filtering.

        Filters are applied in order: ``since`` (only entries with
        monotonic index ``>= since`` -- ``since`` is an inclusive
        lower bound), ``host`` (case-insensitive substring match
        against ``request.host``), ``status_code`` (exact match
        against ``response.status_code``; skips flows with no
        response).

        ``limit`` caps the number of returned entries; pass ``None`` for
        no cap. ``truncated`` is ``True`` when more entries matched than
        were returned.

        ``include_bodies=False`` (default) returns each entry without
        bodies but with ``request_body_truncated`` /
        ``response_body_truncated`` booleans indicating whether a body
        existed. ``include_bodies=True`` inlines bodies, each capped
        at ``max_body_bytes``; UTF-8-decodable bodies come back as
        ``str``, others as ``{"base64": ...}``.

        Returns ``{"flows": [...], "next_since": int, "count": int,
        "total": int, "truncated": bool}``. ``next_since`` is one past
        the largest ``since`` value across the returned entries -- pass
        it back as ``since`` on the next call to tail strictly newer
        flows. When no entries matched, ``next_since`` echoes the input
        ``since`` (or the recorder's current cursor when ``since`` was
        ``None``). ``filename`` writes the JSON payload under the
        output dir and returns only artifact metadata.
        """

        _validate_limit(limit)
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
            if since is not None and isinstance(entry_since, int) and entry_since < since:
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

        if limit is None:
            truncated = False
            selected = matches
        else:
            truncated = len(matches) > limit
            selected = matches[:limit] if limit > 0 else matches[:0]

        result_entries: list[dict] = []
        max_seen: int | None = None
        for entry in selected:
            raw = mgr.flow_by_id(entry.get("id", ""))
            result_entries.append(
                _materialise_entry(entry, raw, include_bodies, max_body_bytes)
            )
            es = entry.get("since")
            if isinstance(es, int) and (max_seen is None or es > max_seen):
                max_seen = es

        if max_seen is not None:
            next_since = max_seen + 1
        elif isinstance(since, int):
            next_since = since
        else:
            next_since = mgr.next_since
        payload = {
            "flows": result_entries,
            "next_since": next_since,
            "count": len(result_entries),
            "total": len(matches),
            "truncated": truncated,
        }
        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            path.write_bytes(data)
            return {
                "path": str(path),
                "bytes": len(data),
                "next_since": next_since,
                "count": payload["count"],
                "total": payload["total"],
                "truncated": truncated,
            }
        return payload

    @capability("proxy-intercept")
    def browser_intercept_flow(
        self,
        flow_id: str,
        include_bodies: bool = True,
        max_body_bytes: int = _DEFAULT_FLOW_BODY_LIMIT,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Return one flow by its mitmproxy-assigned ``flow.id``.

        Defaults to ``include_bodies=True`` so the typical
        "give me everything about this one flow" call gets the body.
        ``max_body_bytes`` caps each body the same way
        :meth:`browser_intercept_flows` does. ``filename`` writes the JSON
        payload under the output dir and returns only artifact metadata.

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
                payload = _materialise_entry(
                    entry, raw, include_bodies, max_body_bytes
                )
                if filename is not None:
                    path = self.config.path_policy.resolve_output(filename)
                    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                    path.write_bytes(data)
                    return {
                        "path": str(path),
                        "bytes": len(data),
                        "flow_id": flow_id,
                    }
                return payload
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

    @capability("proxy-intercept")
    def browser_intercept_replay(
        self,
        flow_id: str,
        *,
        method: ProxyHttpMethod | None = None,
        url: str | None = None,
        http_version: ProxyHttpVersion | None = None,
        set_request_headers: dict[str, str] | None = None,
        remove_request_headers: list[str] | None = None,
        body: str | None = None,
        body_base64: str | None = None,
        timeout: float = _DEFAULT_REPLAY_TIMEOUT,
    ) -> dict[str, Any]:
        """Replay a captured flow as a new request, optionally modified.

        Looks up the source flow by ``flow_id`` in the recorder buffer,
        deep-copies it (the source is not mutated), applies the
        supplied modifications, and dispatches the copy through
        mitmproxy's client-replay path. The dispatched flow surfaces in
        the recorder buffer as a fresh entry with its own monotonic
        ``since`` index and its own id.

        **Response retrieval is asynchronous.** This call returns once
        the dispatched request has been observed by the recorder; the
        upstream response is captured separately on the recorder's own
        event loop and may not yet be attached to the buffered entry
        when this call returns. The inline return therefore contains
        only the dispatched request -- no response. To get the
        response, poll :meth:`browser_intercept_flow` against the
        returned ``replay_flow_id`` after a short wait (a few hundred
        milliseconds is typically enough for a fast endpoint; the
        ``next_action_hint`` field in the return points at this call).

        Modification semantics match :func:`_apply_replay_modifications`:
        ``body`` is UTF-8 encoded, ``body_base64`` is base64-decoded,
        the two are mutually exclusive, and any ``Cookie`` header from
        the source request survives the copy unless explicitly
        overridden via ``set_request_headers`` or removed via
        ``remove_request_headers``.

        Returns ``{"replay_flow_id": str, "source_flow_id": str,
        "since": int, "request": {...}, "next_action_hint": str}``.
        The echoed ``request`` dict carries ``method``, ``url``,
        ``http_version``, and the final headers as a list of
        ``[name, value]`` pairs. ``next_action_hint`` is the literal
        string ``"fetch_response_via_intercept_flow"``.

        Raises :class:`ValueError` for an unknown ``flow_id``, for a
        synthetic ``tls_failed_client`` entry that has no raw flow to
        replay, or for any invalid modification value. Raises
        :class:`ProxyInterceptError` when the substrate is not running
        or when the replay does not complete within ``timeout``.
        """

        if not isinstance(flow_id, str) or not flow_id:
            raise ValueError("flow_id must be a non-empty string")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise ValueError("timeout must be a number")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        self._proxy_alive_check()
        mgr = self._proxy_manager
        assert mgr is not None

        source_flow = mgr.flow_by_id(flow_id)
        if source_flow is None:
            raise ValueError(
                f"flow_id {flow_id!r} is not in the recorder buffer"
                f" (or refers to a synthetic entry with no raw flow)"
            )

        replay_flow = source_flow.copy()
        _apply_replay_modifications(
            replay_flow,
            **{
                k: v
                for k, v in {
                    "method": method,
                    "url": url,
                    "http_version": http_version,
                    "set_request_headers": set_request_headers,
                    "remove_request_headers": remove_request_headers,
                    "body": body,
                    "body_base64": body_base64,
                }.items()
                if v is not None
            },
        )

        new_id = mgr.replay_flow(replay_flow, timeout=float(timeout))

        new_since: int | None = None
        for entry in mgr.flow_buffer:
            if entry.get("id") == new_id:
                es = entry.get("since")
                if isinstance(es, int):
                    new_since = es
                break

        return {
            "replay_flow_id": new_id,
            "source_flow_id": flow_id,
            "since": new_since if new_since is not None else 0,
            "request": {
                "method": replay_flow.request.method,
                "url": replay_flow.request.url,
                "http_version": replay_flow.request.http_version,
                "headers": [
                    list(item)
                    for item in replay_flow.request.headers.items(multi=True)
                ],
            },
            "next_action_hint": "fetch_response_via_intercept_flow",
        }
