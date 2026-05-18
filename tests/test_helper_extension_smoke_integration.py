"""Integration smoke for the helper-extension capability.

Exercises the helper-extension WebSocket bridge against a real Tor
Browser + bundled tor. Opt-in: skipped unless ``TBB_ROOT`` points at an
extracted Tor Browser bundle. Set ``GECKODRIVER_PATH`` if geckodriver
is not on ``PATH``. Run with ``pytest -m integration``.

Uses control/SOCKS ports 9256/9257 and bridge port 9258 so it does not
collide with the existing driver smoke (9250/9251), MCP wire smoke
(9252/9253), or optional-caps smoke (9254/9255). Future helper tools
(observation, active routes) grow into this file as they land.
"""

from __future__ import annotations

import base64
import os
import socket
import time
from pathlib import Path
from typing import Iterator

import pytest

from torbrowser_driver import (
    DEFAULT_CAPABILITIES,
    DriverConfig,
    PathPolicy,
    TorBrowserDriver,
)


pytestmark = pytest.mark.integration


SOCKS_PORT = 9256
CONTROL_PORT = 9257
BRIDGE_PORT = 9258


@pytest.fixture(scope="module")
def tbb_root() -> Path:
    raw = os.environ.get("TBB_ROOT")
    if not raw:
        pytest.skip("TBB_ROOT not set")
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        pytest.skip(f"TBB_ROOT {root} does not exist")
    return root


@pytest.fixture(scope="module")
def geckodriver_path() -> Path | None:
    raw = os.environ.get("GECKODRIVER_PATH")
    if not raw:
        return None
    p = Path(raw).expanduser().resolve()
    if not p.is_file():
        pytest.skip(f"GECKODRIVER_PATH {p} does not exist")
    return p


@pytest.fixture(scope="module")
def drv(
    tbb_root: Path,
    geckodriver_path: Path | None,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[TorBrowserDriver]:
    """Boot one Tor Browser session with helper-extension enabled."""

    base = tmp_path_factory.mktemp("helper-extension-smoke")
    policy = PathPolicy.from_config(output_dir=base / "out", cwd=base)
    config = DriverConfig(
        tbb_root=tbb_root,
        path_policy=policy,
        geckodriver_path=geckodriver_path,
        headless=False,
        socks_port=SOCKS_PORT,
        control_port=CONTROL_PORT,
        helper_bridge_port=BRIDGE_PORT,
        enabled_caps=DEFAULT_CAPABILITIES | {"helper-extension"},
    )

    with TorBrowserDriver(config) as driver:
        yield driver


def _port_is_listening(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((host, port))
        return True
    except (OSError, socket.timeout):
        return False
    finally:
        sock.close()


def test_helper_bridge_connects_and_pings(drv: TorBrowserDriver) -> None:
    """Bridge is up, the extension dialled back, and ping round-trips."""

    bridge = drv._helper_bridge
    assert bridge is not None, "helper bridge should be constructed when cap is enabled"
    assert bridge.connected, "extension should have completed the hello handshake by now"

    response = bridge.request("ping", {}, timeout=5.0)
    assert response.get("ok") is True or "pong" in str(response), (
        f"expected a pong-shaped response, got {response!r}"
    )


def test_helper_bridge_port_freed_on_teardown(
    tbb_root: Path,
    geckodriver_path: Path | None,
    tmp_path: Path,
) -> None:
    """Closing the driver releases the bridge port (no orphan listener)."""

    policy = PathPolicy.from_config(output_dir=tmp_path / "out", cwd=tmp_path)
    teardown_port = BRIDGE_PORT + 100
    config = DriverConfig(
        tbb_root=tbb_root,
        path_policy=policy,
        geckodriver_path=geckodriver_path,
        headless=False,
        socks_port=SOCKS_PORT + 100,
        control_port=CONTROL_PORT + 100,
        helper_bridge_port=teardown_port,
        enabled_caps=DEFAULT_CAPABILITIES | {"helper-extension"},
    )

    with TorBrowserDriver(config) as driver:
        assert driver._helper_bridge is not None
        assert driver._helper_bridge.connected
        assert _port_is_listening("127.0.0.1", teardown_port)

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not _port_is_listening("127.0.0.1", teardown_port):
            return
        time.sleep(0.1)
    pytest.fail(f"bridge port {teardown_port} still listening after driver close")


def _data_url(html: str) -> str:
    encoded = base64.b64encode(html.encode("utf-8")).decode("ascii")
    return "data:text/html;base64," + encoded


def test_helper_extension_captures_check_torproject_response_body(
    drv: TorBrowserDriver,
) -> None:
    """A capture against check.torproject.org surfaces the request body.

    Exercises the capture lifecycle end-to-end: capture start, navigation
    plus a page-context ``fetch('/')`` that touches the same origin,
    and capture stop returning per-request envelopes with headers,
    status, and response body. The fetch call is the bytes-bearing path
    here -- on TB 15.x ``webRequest.filterResponseData`` does not
    deliver bytes, so body capture rides the page-world override the
    helper extension injects at ``document_start``. The matched entry
    must have ``source`` of ``"merged"`` (webRequest + page-world body)
    or ``"page"`` (page-world only).
    """

    drv.browser_navigate("https://check.torproject.org/")

    capture_id = drv.browser_network_capture_start(
        patterns=["https://check.torproject.org/*"],
        capture_response_body=True,
        max_body_bytes=5 * 1024 * 1024,
    )["capture_id"]

    page_body = None
    try:
        drv.webdriver.set_script_timeout(20)
        page_body = drv.webdriver.execute_async_script(
            """
            const cb = arguments[arguments.length - 1];
            fetch('/', {cache: 'no-store'})
              .then(function (r) { return r.text(); })
              .then(function (t) { cb(t); })
              .catch(function (e) { cb({error: String(e)}); });
            """
        )
    finally:
        time.sleep(2.0)
        result = drv.browser_network_capture_stop(capture_id)

    assert isinstance(page_body, str), f"page-side fetch did not return text: {page_body!r}"
    assert ("Congratulations" in page_body) or ("Sorry" in page_body)

    entries = result["entries"]
    assert entries, "expected at least one captured entry"
    matching = [
        e
        for e in entries
        if e["url"] == "https://check.torproject.org/"
        and e["method"] == "GET"
    ]
    assert matching, (
        f"no captured entry for https://check.torproject.org/ GET; "
        f"saw urls={[e['url'] for e in entries]!r}"
    )
    bodied = [e for e in matching if isinstance(e["response_body"], str) and e["response_body"]]
    assert bodied, (
        "no captured entry carried a non-empty response_body; "
        f"sources={[e.get('source') for e in matching]!r}, "
        f"bodies={[type(e.get('response_body')).__name__ for e in matching]!r}"
    )
    entry = bodied[-1]
    assert ("Congratulations" in entry["response_body"]) or (
        "Sorry" in entry["response_body"]
    ), f"response_body missing tor-exit marker: head={entry['response_body'][:200]!r}"
    assert entry["source"] in ("merged", "page"), (
        f"expected source merged or page, got {entry['source']!r}"
    )
    if entry["source"] == "merged":
        assert entry["response_headers"], "merged entry should keep webRequest headers"
        assert entry["response_headers"].get("Content-Type", "").startswith("text/html")
        assert entry["status_code"] == 200


def test_helper_extension_captures_xhr_response_body(
    drv: TorBrowserDriver,
) -> None:
    """A page-initiated XMLHttpRequest surfaces its response body.

    Navigates to ``check.torproject.org`` so an XHR to ``/`` is
    same-origin, then drives the XHR from page context via Selenium's
    ``execute_async_script`` and waits for ``loadend``. After
    ``browser_network_capture_stop`` the matching entry must carry the
    tor-exit marker in its ``response_body``. The body comes from the
    page-world XHR override the helper injects at ``document_start``;
    the entry surfaces as ``source="merged"`` when webRequest also saw
    the request, or ``source="page"`` otherwise.
    """

    drv.browser_navigate("https://check.torproject.org/")

    capture_id = drv.browser_network_capture_start(
        patterns=["https://check.torproject.org/*"],
        capture_response_body=True,
        max_body_bytes=5 * 1024 * 1024,
    )["capture_id"]

    page_status = None
    try:
        drv.webdriver.set_script_timeout(30)
        page_status = drv.webdriver.execute_async_script(
            """
            const cb = arguments[arguments.length - 1];
            try {
              var x = new XMLHttpRequest();
              x.open('GET', '/?xhr-probe=' + Date.now());
              x.onloadend = function () {
                cb({status: x.status, body: x.responseText || '', url: x.responseURL});
              };
              x.onerror = function () {
                cb({status: -1, body: '', error: 'xhr-onerror'});
              };
              x.send();
            } catch (e) {
              cb({status: -1, body: '', error: String(e)});
            }
            """
        )
    finally:
        time.sleep(2.0)
        result = drv.browser_network_capture_stop(capture_id)

    assert isinstance(page_status, dict), f"xhr never completed: {page_status!r}"
    assert page_status.get("status") == 200, page_status
    page_body_text = page_status.get("body") or ""
    assert ("Congratulations" in page_body_text) or ("Sorry" in page_body_text)

    entries = result["entries"]
    assert entries, "expected at least one captured entry from XHR"
    matching = [
        e
        for e in entries
        if isinstance(e["url"], str)
        and e["url"].startswith("https://check.torproject.org/")
        and "xhr-probe=" in e["url"]
        and e["method"] == "GET"
    ]
    assert matching, (
        f"no captured entry for the XHR target; urls={[e['url'] for e in entries]!r}"
    )
    bodied = [
        e for e in matching if isinstance(e["response_body"], str) and e["response_body"]
    ]
    assert bodied, (
        "no captured XHR entry carried a non-empty response_body; "
        f"sources={[e.get('source') for e in matching]!r}"
    )
    entry = bodied[-1]
    assert ("Congratulations" in entry["response_body"]) or (
        "Sorry" in entry["response_body"]
    )
    assert entry["source"] in ("merged", "page")


def test_helper_extension_init_script_runs_at_document_start(
    drv: TorBrowserDriver,
) -> None:
    """An init script runs before page JS on the next navigation.

    Verifies the script reaches page world by having the content script
    inject a ``<script>`` tag into ``document.documentElement`` at
    document_start; Selenium's ``execute_script`` then reads the
    page-world global the inline script set. Uses a file:// URL written
    under the path policy's output_dir because MV2 content scripts do
    not inject into ``data:`` URLs in Firefox.
    """

    source = (
        "(function(){"
        "var s = document.createElement('script');"
        "s.textContent = 'window.__tbm_init = (window.__tbm_init || 0) + 1;';"
        "document.documentElement.appendChild(s);"
        "if (s.parentNode) s.parentNode.removeChild(s);"
        "})();"
    )
    page_path = drv.config.path_policy.resolve_output("init-script-fixture.html")
    page_path.write_text("<html><body>hi</body></html>", encoding="utf-8")
    file_url = page_path.as_uri()

    script_id = drv.browser_add_init_script(source=source)["script_id"]
    try:
        drv.browser_navigate(file_url)
        time.sleep(0.5)
        count = drv.webdriver.execute_script("return window.__tbm_init;")
        assert count == 1, f"expected init script to run exactly once, got {count!r}"
    finally:
        removed = drv.browser_remove_init_script(script_id)
        assert removed == {"removed": True}


def test_helper_extension_routes_fetch_to_mocked_body(
    drv: TorBrowserDriver,
) -> None:
    """A mock route answers a page-context fetch with the registered body.

    The driver registers the mock body on the bridge's ``/mock/<id>``
    endpoint and tells the extension to redirect matching requests
    there. After unrouting, the same fetch must fail because the
    redirect rule is gone and ``example.invalid`` does not resolve.

    The page is loaded from the bridge's own ``/host`` endpoint so the
    fetch and the redirect's terminal target both sit on the bridge
    origin -- ``data:`` URL documents cannot make cross-origin
    page-context fetches in Tor Browser, which would otherwise mask
    the mock-mode behaviour under network errors.
    """

    drv.browser_navigate(f"http://127.0.0.1:{drv._helper_bridge.port}/host")

    route = drv.browser_route(
        "*://example.invalid/*",
        body="ok",
        content_type="text/plain",
    )
    route_id = route["route_id"]
    assert isinstance(route_id, str) and route_id

    listed = drv.browser_route_list()
    assert any(r["route_id"] == route_id for r in listed)

    drv.webdriver.set_script_timeout(15)
    page_body = drv.webdriver.execute_async_script(
        """
        const cb = arguments[arguments.length - 1];
        fetch('http://example.invalid/', {cache: 'no-store'})
          .then(function (r) { return r.text(); })
          .then(function (t) { cb({ok: true, body: t}); })
          .catch(function (e) { cb({ok: false, error: String(e)}); });
        """
    )
    assert isinstance(page_body, dict) and page_body.get("ok") is True, (
        f"fetch should resolve to the mocked body, got {page_body!r}"
    )
    assert page_body.get("body") == "ok", page_body

    removed = drv.browser_unroute(pattern="*://example.invalid/*")
    assert removed == {"removed": 1}

    after = drv.webdriver.execute_async_script(
        """
        const cb = arguments[arguments.length - 1];
        fetch('http://example.invalid/', {cache: 'no-store'})
          .then(function (r) { return r.text(); })
          .then(function (t) { cb({ok: true, body: t}); })
          .catch(function (e) { cb({ok: false, error: String(e)}); });
        """
    )
    assert isinstance(after, dict) and after.get("ok") is False, (
        f"fetch should fail with a network error after unroute, got {after!r}"
    )


def test_helper_extension_mock_serves_custom_status_and_headers(
    drv: TorBrowserDriver,
) -> None:
    """Mock-mode delivers arbitrary status, headers, and body.

    Bridge-served mocks carry the full HTTP envelope -- the page
    observes the registered status code and any user-supplied headers
    alongside the response body.
    """

    drv.browser_navigate(f"http://127.0.0.1:{drv._helper_bridge.port}/host")

    route = drv.browser_route(
        "*://example.invalid/*",
        status=404,
        body='{"error":"not found"}',
        content_type="application/json",
        headers={"X-Test-Header": "tor-browser-mcp"},
    )
    route_id = route["route_id"]
    try:
        drv.webdriver.set_script_timeout(15)
        observed = drv.webdriver.execute_async_script(
            """
            const cb = arguments[arguments.length - 1];
            fetch('http://example.invalid/lookup', {cache: 'no-store'})
              .then(function (r) {
                return r.text().then(function (text) {
                  return {
                    ok: true,
                    status: r.status,
                    body: text,
                    content_type: r.headers.get('Content-Type'),
                    custom: r.headers.get('X-Test-Header'),
                  };
                });
              })
              .catch(function (e) { cb({ok: false, error: String(e)}); })
              .then(function (v) { cb(v); });
            """
        )
    finally:
        drv.browser_unroute(route_id=route_id)

    assert isinstance(observed, dict) and observed.get("ok") is True, observed
    assert observed.get("status") == 404, observed
    assert observed.get("body") == '{"error":"not found"}', observed
    assert observed.get("content_type") == "application/json", observed
    assert observed.get("custom") == "tor-browser-mcp", observed


def test_helper_extension_offline_mode_blocks_new_navigation(
    drv: TorBrowserDriver,
) -> None:
    """``offline`` cancels new network requests; ``online`` restores them.

    Exercised at the ``fetch()`` layer rather than ``browser_navigate``
    because Firefox's response to a cancelled top-level navigation is
    a hung page-load that surfaces as a Selenium read timeout only
    after the urllib3 default (~120 s). A page-context fetch raises
    immediately and is the primitive the cap actually intends to
    block. A ``data:`` URL navigation is used after restore: ``data:``
    URLs bypass ``webRequest`` entirely and are the deterministic way
    to prove the offline listener was removed.
    """

    drv.browser_navigate(_data_url("<html><body>start</body></html>"))

    drv.browser_network_state_set("offline")
    try:
        drv.webdriver.set_script_timeout(15)
        offline_probe = drv.webdriver.execute_async_script(
            """
            const cb = arguments[arguments.length - 1];
            fetch('http://example.invalid/offline-probe', {cache: 'no-store'})
              .then(function (r) { return r.text(); })
              .then(function (t) { cb({ok: true, body: t}); })
              .catch(function (e) { cb({ok: false, error: String(e)}); });
            """
        )
        assert (
            isinstance(offline_probe, dict) and offline_probe.get("ok") is False
        ), f"fetch should fail while offline, got {offline_probe!r}"
    finally:
        drv.browser_network_state_set("online")

    after = drv.browser_navigate(_data_url("<html><body>back</body></html>"))
    assert after["url"].startswith("data:")
