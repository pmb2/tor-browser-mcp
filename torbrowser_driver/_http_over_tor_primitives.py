"""Raw-HTTP-through-Tor primitives implementing the ``http-over-tor`` capability.

These tools issue HTTP requests through the bundled tor's SOCKS port via
:class:`urllib3.contrib.socks.SOCKSProxyManager`. They are useful for
replay, IOC probing, and lightweight API calls that need Tor routing but
not a full browser navigation.

Limitations - **these are Tor-routed but not browser-equivalent**:

* No TLS-state continuity with the live browser session; each request
  performs its own TLS handshake from the urllib3 pool.
* No service workers, no DOM, no caches, no IndexedDB.
* No JavaScript execution.
* TLS and HTTP fingerprint differ from Tor Browser's (different cipher
  suites, ALPN preferences, header ordering, User-Agent default).
* The cookie store implemented here is a minimal ``host -> {name: value}``
  jar; ``Path``/``Domain``/``Expires``/``Secure``/``HttpOnly`` are
  ignored, latest write wins.

Use the browser navigation primitives when fingerprint parity with Tor
Browser matters; reach for these tools when raw, scriptable HTTP through
the Tor SOCKS endpoint is genuinely what you want.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any, Literal, TypedDict
from urllib.parse import urljoin, urlparse

from urllib3.contrib.socks import SOCKSProxyManager

from .capabilities import capability
from .exceptions import TorBrowserDriverError

if TYPE_CHECKING:
    from collections.abc import Iterator

    import urllib3
    from selenium import webdriver

    from .config import DriverConfig


HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


class HttpSequenceRequestRequired(TypedDict):
    url: str


class HttpSequenceRequest(HttpSequenceRequestRequired, total=False):
    method: HttpMethod
    headers: dict[str, str]
    body: str
    timeout: float
    max_response_bytes: int


_DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


_ALLOWED_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)

_TEXTUAL_HINTS: tuple[str, ...] = ("text/", "json", "xml", "javascript")

_MAX_REDIRECTS = 10


def _is_textual_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    lowered = content_type.lower()
    return any(hint in lowered for hint in _TEXTUAL_HINTS)


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _validate_http_url(url: str) -> None:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"url must be an absolute http(s) URL, got {url!r}")


def _strip_leading_dot(domain: str) -> str:
    return domain.lstrip(".").lower() if domain else ""


def _parse_set_cookie(value: str) -> tuple[str, str] | None:
    """Pull ``(name, value)`` out of one ``Set-Cookie`` line.

    Drops ``Path``/``Domain``/``Expires``/``Secure``/``HttpOnly`` and the
    rest of the attribute set; this jar is intentionally minimal.
    """

    head = value.split(";", 1)[0].strip()
    if "=" not in head:
        return None
    name, _, val = head.partition("=")
    name = name.strip()
    if not name:
        return None
    return name, val.strip()


def _iter_set_cookie(
    headers: urllib3.HTTPHeaderDict | dict[str, str],
) -> Iterator[str]:
    """Yield each ``Set-Cookie`` header value, handling multi-valued headers."""

    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        yield from getlist("Set-Cookie")
        return
    raw = headers.get("Set-Cookie") if hasattr(headers, "get") else None
    if not raw:
        return
    yield raw


def _flatten_headers(
    headers: urllib3.HTTPHeaderDict | dict[str, str],
) -> dict[str, str]:
    """Return ``{name: value}`` with multi-valued headers comma-joined."""

    out: dict[str, str] = {}
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        seen: set[str] = set()
        for name in headers.keys():  # noqa: SIM118  # headers stub exposes .keys() but is not iterable
            lower = name.lower()
            if lower in seen:
                continue
            seen.add(lower)
            values = getlist(name)
            out[name] = ", ".join(values) if values else ""
        return out
    for name, value in headers.items():
        out[name] = value
    return out


def _cookie_header_from_jar(
    jar: dict[str, dict[str, str]], host: str
) -> str | None:
    """Render a ``Cookie`` header for ``host`` from the in-memory jar."""

    pairs = jar.get(host)
    if not pairs:
        return None
    return "; ".join(f"{name}={value}" for name, value in pairs.items())


def _merge_browser_cookies(
    jar: dict[str, dict[str, str]], cookies: list[dict[str, Any]]
) -> None:
    """Pour ``webdriver.get_cookies()`` output into the in-memory jar."""

    for c in cookies:
        name = c.get("name")
        value = c.get("value")
        if not name:
            continue
        host = _strip_leading_dot(str(c.get("domain") or ""))
        if not host:
            continue
        jar.setdefault(host, {})[str(name)] = "" if value is None else str(value)


class _HttpOverTorCapabilityMixin:
    """Implements the ``http-over-tor`` capability surface on :class:`TorBrowserDriver`.

    The proxy manager is built lazily per call so a ``NEWNYM``-driven
    rotation of the bundled tor takes effect on the next request without
    needing to reset any cached state.
    """

    if TYPE_CHECKING:
        webdriver: webdriver.Firefox | None
        config: DriverConfig

        def _require_driver(self) -> webdriver.Firefox: ...

    def _build_proxy_manager(self) -> SOCKSProxyManager:
        proxy_url = f"socks5h://127.0.0.1:{int(self.config.socks_port)}"
        return SOCKSProxyManager(proxy_url)

    def _normalise_method(self, method: str) -> str:
        upper = method.upper()
        if upper not in _ALLOWED_METHODS:
            raise ValueError(
                f"unsupported HTTP method {method!r}; allowed: "
                f"{sorted(_ALLOWED_METHODS)}"
            )
        return upper

    def _serialise_response(
        self,
        url: str,
        response: Any,
        max_response_bytes: int,
    ) -> dict[str, Any]:
        """Read ``response`` up to ``max_response_bytes`` and pack a result dict.

        ``response`` is expected to behave like a ``urllib3`` HTTPResponse
        opened with ``preload_content=False``; ``.read(amt)`` is called
        with a one-byte overflow probe so truncation can be reported
        accurately. The connection is released on the way out.
        """

        headers = _flatten_headers(response.headers)
        try:
            cap = max(0, int(max_response_bytes))
            try:
                data = response.read(cap + 1)
            except TypeError:
                data = response.read()
        finally:
            release = getattr(response, "release_conn", None)
            if callable(release):
                try:
                    release()
                except Exception:
                    pass

        data = data or b""
        truncated = len(data) > cap
        if truncated:
            data = data[:cap]

        content_type = None
        for k, v in headers.items():
            if k.lower() == "content-type":
                content_type = v
                break

        result: dict[str, Any] = {
            "status": int(getattr(response, "status", 0)),
            "headers": headers,
            "url": url,
            "body_bytes": len(data),
        }
        if truncated:
            result["truncated"] = True

        if _is_textual_content_type(content_type):
            try:
                result["body"] = data.decode("utf-8")
            except UnicodeDecodeError:
                result["body"] = data.decode("utf-8", errors="replace")
        elif len(data) == 0:
            result["body"] = ""
        else:
            result["body_base64"] = base64.b64encode(data).decode("ascii")

        return result

    def _issue_one(
        self,
        manager: SOCKSProxyManager,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: str | bytes | None,
        timeout: float,
        max_response_bytes: int,
        jar: dict[str, dict[str, str]] | None,
        caller_cookie: str | None,
    ) -> dict[str, Any]:
        """Issue one request with manual redirect handling.

        Follows up to :data:`_MAX_REDIRECTS` redirects, returning a result
        whose ``redirect_chain`` lists each ``Location`` followed. Cookies
        in ``jar`` are layered into the ``Cookie`` header on each hop
        unless the caller supplied one explicitly. When ``jar`` is not
        ``None``, ``Set-Cookie`` responses are merged back into it as the
        chain progresses.
        """

        current_url = url
        redirect_chain: list[str] = []
        body_bytes: bytes | None
        if body is None:
            body_bytes = None
        elif isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
        else:
            body_bytes = body.encode("utf-8")

        for _ in range(_MAX_REDIRECTS + 1):
            host = _host_of(current_url)
            req_headers: dict[str, str] = {}
            if headers:
                for k, v in headers.items():
                    req_headers[str(k)] = str(v)

            existing_cookie = None
            for k in list(req_headers.keys()):
                if k.lower() == "cookie":
                    existing_cookie = req_headers.pop(k)

            cookie_value = caller_cookie if caller_cookie is not None else existing_cookie
            if cookie_value is None and jar is not None:
                cookie_value = _cookie_header_from_jar(jar, host)
            if cookie_value:
                req_headers["Cookie"] = cookie_value

            response = manager.request(
                method,
                current_url,
                headers=req_headers or None,
                body=body_bytes,
                redirect=False,
                preload_content=False,
                timeout=float(timeout),
            )

            if jar is not None:
                for raw_set in _iter_set_cookie(response.headers):
                    parsed = _parse_set_cookie(raw_set)
                    if parsed is None:
                        continue
                    name, value = parsed
                    jar.setdefault(host, {})[name] = value

            status = int(getattr(response, "status", 0))
            location = None
            for k, v in response.headers.items() if hasattr(response.headers, "items") else []:
                if k.lower() == "location":
                    location = v
                    break

            if 300 <= status < 400 and location:
                next_str = urljoin(current_url, location)
                scheme = (urlparse(next_str).scheme or "").lower()
                if scheme not in ("http", "https"):
                    try:
                        response.release_conn()
                    except Exception:
                        pass
                    raise ValueError(
                        f"refusing redirect to non-http(s) scheme {scheme!r}: "
                        f"{location!r}"
                    )
                try:
                    response.release_conn()
                except Exception:
                    pass
                redirect_chain.append(next_str)
                current_url = next_str
                continue

            result = self._serialise_response(
                current_url, response, max_response_bytes
            )
            result["redirect_chain"] = redirect_chain
            return result

        raise TorBrowserDriverError(
            f"exceeded {_MAX_REDIRECTS} redirects starting from {url!r}"
        )

    @capability("http-over-tor")
    def tor_http_request(
        self,
        method: HttpMethod,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        use_browser_cookies: bool = False,
        timeout: float = 60.0,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Issue a single HTTP request through the bundled tor's SOCKS port.

        ``method`` is upper-cased and must be one of ``GET``, ``POST``,
        ``PUT``, ``DELETE``, ``PATCH``, ``HEAD``, ``OPTIONS``. ``body``
        accepts ``str`` (encoded as UTF-8) or ``bytes``. Redirects are
        followed manually up to ten hops; each ``Location`` is recorded in
        ``redirect_chain``. Non-http(s) redirect targets raise
        :class:`ValueError`. Response bodies are decoded as UTF-8 when the
        ``Content-Type`` looks textual (``text/*``, ``*json*``, ``*xml*``,
        ``*javascript*``) and packed into ``body``; otherwise the bytes go
        into ``body_base64``. Captured response bytes are capped at
        ``max_response_bytes`` and ``truncated: True`` flags clipping.

        When ``use_browser_cookies`` is set, cookies from the live browser
        session are read via ``webdriver.get_cookies()`` and serialised
        into a ``Cookie`` header keyed by host; a caller-supplied
        ``Cookie`` header in ``headers`` takes precedence per hop.

        ``filename`` writes the raw response body to disk and returns the
        same per-request summary with ``body``/``body_base64`` replaced by
        ``{"path": str, "bytes": int}``.

        This is **Tor-routed but not browser-equivalent**: no DOM, no JS,
        no service workers, no cache, and the TLS/HTTP fingerprint differs
        from Tor Browser's. Use the navigation primitives when fingerprint
        parity matters.
        """

        _validate_http_url(url)
        normalised = self._normalise_method(method)
        manager = self._build_proxy_manager()

        caller_cookie: str | None = None
        if headers:
            for k, v in headers.items():
                if k.lower() == "cookie":
                    caller_cookie = str(v)
                    break

        jar: dict[str, dict[str, str]] | None = None
        if use_browser_cookies:
            drv = self._require_driver()
            jar = {}
            try:
                browser_cookies = list(drv.get_cookies() or [])
            except Exception:
                browser_cookies = []
            _merge_browser_cookies(jar, browser_cookies)

        result = self._issue_one(
            manager,
            normalised,
            url,
            headers,
            body,
            timeout,
            max_response_bytes,
            jar,
            caller_cookie,
        )

        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            payload = (
                result.get("body")
                if "body" in result
                else base64.b64decode(result.get("body_base64", ""))
            )
            data = payload.encode("utf-8") if isinstance(payload, str) else (payload or b"")
            path.write_bytes(data)
            summary = {
                k: v
                for k, v in result.items()
                if k not in ("body", "body_base64")
            }
            summary.update({"path": str(path), "bytes": len(data)})
            return summary
        return result

    @capability("http-over-tor")
    def tor_http_sequence(
        self,
        requests: list[HttpSequenceRequest],
        cookie_jar: bool = True,
        use_browser_cookies: bool = False,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Issue an ordered batch of HTTP requests through tor.

        Each entry in ``requests`` accepts the same keys as the parameters
        of :meth:`tor_http_request` minus ``use_browser_cookies`` and
        ``filename`` (which live on this outer call). Defaults applied per
        entry: ``method`` falls back to ``"GET"``, ``timeout`` to ``60.0``,
        ``max_response_bytes`` to 5 MiB.

        When ``cookie_jar`` is true, response ``Set-Cookie`` headers are
        parsed and forwarded as ``Cookie`` headers into later requests,
        keyed by the request host (latest write wins, no Path/Expires
        logic - this jar is for replay/probing, not RFC-grade cookie
        management). ``use_browser_cookies`` seeds the jar from
        ``webdriver.get_cookies()`` before the first request runs.

        Returns ``{"results": [<per-request dict>], "final_cookie_jar":
        {host: {name: value}}}``. When ``filename`` is set the full
        results JSON is written under the output dir and the inline
        ``results`` list is dropped; the returned dict carries
        ``{"path": str, "bytes": int, "results_count": int,
        "final_cookie_jar": ...}``.

        Same fingerprint caveats as :meth:`tor_http_request` apply.
        """

        if not isinstance(requests, list):
            raise ValueError("requests must be a list of dicts")

        manager = self._build_proxy_manager()
        jar: dict[str, dict[str, str]] | None
        jar = {} if cookie_jar else None

        if use_browser_cookies and cookie_jar:
            drv = self._require_driver()
            try:
                browser_cookies = list(drv.get_cookies() or [])
            except Exception:
                browser_cookies = []
            _merge_browser_cookies(jar, browser_cookies)

        results: list[dict[str, Any]] = []
        for entry in requests:
            if not isinstance(entry, dict):
                raise ValueError(
                    f"each requests entry must be a dict; got {type(entry).__name__}"
                )
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                raise ValueError("each requests entry must include a non-empty 'url'")
            _validate_http_url(url)
            method = self._normalise_method(str(entry.get("method", "GET")))
            headers = entry.get("headers")
            body = entry.get("body")
            timeout = float(entry.get("timeout", 60.0))
            max_response_bytes = int(
                entry.get("max_response_bytes", _DEFAULT_MAX_RESPONSE_BYTES)
            )

            caller_cookie: str | None = None
            if isinstance(headers, dict):
                for k, v in headers.items():
                    if str(k).lower() == "cookie":
                        caller_cookie = str(v)
                        break

            result = self._issue_one(
                manager,
                method,
                url,
                headers if isinstance(headers, dict) else None,
                body,
                timeout,
                max_response_bytes,
                jar,
                caller_cookie,
            )
            results.append(result)

        final_jar: dict[str, dict[str, str]] = jar if jar is not None else {}
        out: dict[str, Any] = {
            "results": results,
            "final_cookie_jar": final_jar,
        }
        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(out, ensure_ascii=False).encode("utf-8")
            path.write_bytes(data)
            return {
                "path": str(path),
                "bytes": len(data),
                "results_count": len(results),
                "final_cookie_jar": final_jar,
            }
        return out
