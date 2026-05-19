"""Tests for the ``http-over-tor`` capability driver primitives.

All HTTP is mocked at the SOCKS-proxy-manager boundary; no test in this
module performs a real network call.
"""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from torbrowser_driver import PathPolicy, TorBrowserDriver, TorBrowserDriverError


class _FakeConfig(SimpleNamespace):
    pass


@pytest.fixture()
def policy(tmp_path: Path) -> PathPolicy:
    out = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    return PathPolicy.from_config(output_dir=out, cwd=work)


@pytest.fixture()
def drv(policy: PathPolicy) -> TorBrowserDriver:
    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = _FakeConfig(
        path_policy=policy, socks_port=9999
    )  # type: ignore[assignment]
    instance.webdriver = MagicMock(name="webdriver")
    instance.controller = None
    instance._closed = False
    instance._tor_process = None
    instance._session_dir = None
    instance._owns_session_dir = False
    instance._owns_tor_data_dir = False
    return instance


class _StubHeaders:
    """Minimal urllib3 HTTPHeaderDict stand-in.

    Supports ``items``, ``get``, ``getlist``, and dict-style iteration so
    the mixin's header walker exercises the multi-valued ``Set-Cookie``
    path without depending on a real ``HTTPHeaderDict``.
    """

    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = list(items)

    def keys(self):
        seen: set[str] = set()
        out: list[str] = []
        for k, _ in self._items:
            if k.lower() in seen:
                continue
            seen.add(k.lower())
            out.append(k)
        return out

    def items(self):
        return list(self._items)

    def get(self, name: str, default: Any = None) -> Any:
        for k, v in self._items:
            if k.lower() == name.lower():
                return v
        return default

    def getlist(self, name: str) -> list[str]:
        return [v for k, v in self._items if k.lower() == name.lower()]


class _StubResponse:
    """Stand-in for a urllib3 ``HTTPResponse`` opened with preload=False."""

    def __init__(
        self,
        status: int,
        headers: list[tuple[str, str]] | None = None,
        body: bytes = b"",
    ) -> None:
        self.status = status
        self.headers = _StubHeaders(headers or [])
        self._body = body
        self.released = False

    def read(self, amt: int | None = None) -> bytes:
        if amt is None:
            data = self._body
            self._body = b""
            return data
        data = self._body[:amt]
        self._body = self._body[amt:]
        return data

    def release_conn(self) -> None:
        self.released = True


class _StubManager:
    """Records calls and serves a queue of stub responses in order."""

    def __init__(self, responses: list[_StubResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _StubResponse:
        if not self._responses:
            raise AssertionError(
                f"unexpected extra request: {method} {url}"
            )
        self.calls.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


def _patch_manager(
    drv: TorBrowserDriver, responses: list[_StubResponse]
) -> _StubManager:
    manager = _StubManager(responses)
    drv._build_proxy_manager = lambda: manager  # type: ignore[assignment,method-assign]
    return manager


def test_textual_response_decodes_to_body(drv: TorBrowserDriver) -> None:
    response = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/html; charset=utf-8")],
        body=b"<html><body>ok</body></html>",
    )
    manager = _patch_manager(drv, [response])

    result = drv.tor_http_request(method="GET", url="https://example.test/")
    assert result["status"] == 200
    assert result["body"] == "<html><body>ok</body></html>"
    assert "body_base64" not in result
    assert result["redirect_chain"] == []
    assert result["body_bytes"] == len(b"<html><body>ok</body></html>")
    assert manager.calls[0]["method"] == "GET"
    assert manager.calls[0]["redirect"] is False
    assert manager.calls[0]["preload_content"] is False


def test_binary_response_goes_to_body_base64(drv: TorBrowserDriver) -> None:
    payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    response = _StubResponse(
        status=200,
        headers=[("Content-Type", "image/png")],
        body=payload,
    )
    _patch_manager(drv, [response])

    result = drv.tor_http_request(method="GET", url="https://example.test/x.png")
    assert "body" not in result
    assert base64.b64decode(result["body_base64"]) == payload


def test_redirect_chain_accumulates(drv: TorBrowserDriver) -> None:
    hop1 = _StubResponse(
        status=302,
        headers=[("Location", "https://example.test/step2")],
    )
    hop2 = _StubResponse(
        status=302,
        headers=[("Location", "/step3")],
    )
    final = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=b"done",
    )
    manager = _patch_manager(drv, [hop1, hop2, final])

    result = drv.tor_http_request(method="GET", url="https://example.test/start")
    assert result["status"] == 200
    assert result["body"] == "done"
    assert result["redirect_chain"] == [
        "https://example.test/step2",
        "https://example.test/step3",
    ]
    assert [c["url"] for c in manager.calls] == [
        "https://example.test/start",
        "https://example.test/step2",
        "https://example.test/step3",
    ]
    assert all(c["redirect"] is False for c in manager.calls)


def test_redirect_to_non_http_scheme_raises(drv: TorBrowserDriver) -> None:
    response = _StubResponse(
        status=302,
        headers=[("Location", "javascript:alert(1)")],
    )
    _patch_manager(drv, [response])

    with pytest.raises(ValueError, match="non-http"):
        drv.tor_http_request(method="GET", url="https://example.test/")


def test_max_redirect_limit_raises(drv: TorBrowserDriver) -> None:
    hops = [
        _StubResponse(
            status=302,
            headers=[("Location", f"https://example.test/{i + 1}")],
        )
        for i in range(11)
    ]
    _patch_manager(drv, hops)

    with pytest.raises(TorBrowserDriverError, match="redirects"):
        drv.tor_http_request(method="GET", url="https://example.test/0")


def test_oversize_response_truncates(drv: TorBrowserDriver) -> None:
    body = b"A" * 10_000
    response = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=body,
    )
    _patch_manager(drv, [response])

    result = drv.tor_http_request(
        method="GET",
        url="https://example.test/big",
        max_response_bytes=128,
    )
    assert result["truncated"] is True
    assert result["body_bytes"] == 128
    assert result["body"] == "A" * 128


def test_rejected_method_raises(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError, match="HTTP method"):
        drv.tor_http_request(method="TRACE", url="https://example.test/")


def test_method_is_uppercased(drv: TorBrowserDriver) -> None:
    response = _StubResponse(
        status=204,
        headers=[("Content-Type", "text/plain")],
        body=b"",
    )
    manager = _patch_manager(drv, [response])

    drv.tor_http_request(method="post", url="https://example.test/")
    assert manager.calls[0]["method"] == "POST"


def test_use_browser_cookies_serialises_into_cookie_header(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.get_cookies.return_value = [
        {"name": "sid", "value": "abc", "domain": "example.test"},
        {"name": "csrf", "value": "z9", "domain": ".example.test"},
        {"name": "other", "value": "x", "domain": "other.test"},
    ]
    response = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=b"ok",
    )
    manager = _patch_manager(drv, [response])

    drv.tor_http_request(
        method="GET",
        url="https://example.test/path",
        use_browser_cookies=True,
    )

    sent_headers = manager.calls[0]["headers"]
    assert sent_headers is not None
    cookie_value = sent_headers.get("Cookie")
    assert cookie_value is not None
    # Both example.test cookies serialised, the other.test one omitted.
    assert "sid=abc" in cookie_value
    assert "csrf=z9" in cookie_value
    assert "other=x" not in cookie_value


def test_caller_cookie_header_wins_over_browser_cookies(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.get_cookies.return_value = [
        {"name": "sid", "value": "from-browser", "domain": "example.test"},
    ]
    response = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=b"ok",
    )
    manager = _patch_manager(drv, [response])

    drv.tor_http_request(
        method="GET",
        url="https://example.test/path",
        headers={"Cookie": "sid=from-caller"},
        use_browser_cookies=True,
    )
    cookie_value = manager.calls[0]["headers"]["Cookie"]
    assert cookie_value == "sid=from-caller"


def test_sequence_cookie_jar_accumulates_across_steps(
    drv: TorBrowserDriver,
) -> None:
    first = _StubResponse(
        status=200,
        headers=[
            ("Content-Type", "text/plain"),
            ("Set-Cookie", "sid=abc; Path=/; HttpOnly"),
            ("Set-Cookie", "lang=en"),
        ],
        body=b"ok",
    )
    second = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=b"ok2",
    )
    manager = _patch_manager(drv, [first, second])

    out = drv.tor_http_sequence(
        requests=[
            {"url": "https://example.test/login"},
            {"url": "https://example.test/profile"},
        ]
    )

    assert len(out["results"]) == 2
    second_headers = manager.calls[1]["headers"]
    assert second_headers is not None
    cookie_value = second_headers.get("Cookie")
    assert cookie_value is not None
    assert "sid=abc" in cookie_value
    assert "lang=en" in cookie_value
    assert out["final_cookie_jar"]["example.test"] == {"sid": "abc", "lang": "en"}


def test_sequence_cookie_jar_disabled_omits_cookies(
    drv: TorBrowserDriver,
) -> None:
    first = _StubResponse(
        status=200,
        headers=[
            ("Content-Type", "text/plain"),
            ("Set-Cookie", "sid=abc"),
        ],
        body=b"ok",
    )
    second = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=b"ok2",
    )
    manager = _patch_manager(drv, [first, second])

    out = drv.tor_http_sequence(
        requests=[
            {"url": "https://example.test/a"},
            {"url": "https://example.test/b"},
        ],
        cookie_jar=False,
    )
    second_headers = manager.calls[1]["headers"]
    cookie_value = (second_headers or {}).get("Cookie") if second_headers else None
    assert cookie_value is None
    assert out["final_cookie_jar"] == {}


def test_sequence_use_browser_cookies_seeds_jar(drv: TorBrowserDriver) -> None:
    drv.webdriver.get_cookies.return_value = [
        {"name": "pre", "value": "seed", "domain": "example.test"},
    ]
    response = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=b"ok",
    )
    manager = _patch_manager(drv, [response])

    drv.tor_http_sequence(
        requests=[{"url": "https://example.test/x"}],
        use_browser_cookies=True,
    )
    cookie_value = manager.calls[0]["headers"]["Cookie"]
    assert "pre=seed" in cookie_value


def test_sequence_rejects_bad_entry(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError, match="url"):
        drv.tor_http_sequence(requests=[{"method": "GET"}])
    with pytest.raises(ValueError, match="dict"):
        drv.tor_http_sequence(requests=["not-a-dict"])  # type: ignore[list-item]


def test_filename_writes_body_to_disk(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    response = _StubResponse(
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=b"hello",
    )
    _patch_manager(drv, [response])

    result = drv.tor_http_request(
        method="GET",
        url="https://example.test/",
        filename="resp.txt",
    )
    written = Path(result["path"])
    assert written.read_bytes() == b"hello"
    assert written.parent == policy.output_dir
