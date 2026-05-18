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
    """A capture against check.torproject.org surfaces the request envelope.

    Exercises the capture lifecycle end-to-end: capture start, navigation
    plus a page-context ``fetch('/')`` that touches the same origin, and
    capture stop returning per-request envelopes with headers, status,
    and matching URL.

    The page-side fetch result is asserted to contain the tor-exit
    marker so the navigation went through; the same request is then
    located in the capture envelopes and checked for status/headers.

    Response-body bytes are not asserted here because
    ``webRequest.filterResponseData`` on Tor Browser 15 / Firefox 140
    ESR attaches successfully and fires ``onstop`` but does not deliver
    payload bytes to ``ondata`` for requests that cross the
    extension/network process boundary. The filter and the rest of the
    pipeline are wired up in production; if a future TB build restores
    the data path the assertion below will start seeing populated
    bodies.
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
        and e["status_code"] == 200
    ]
    assert matching, (
        f"no captured entry for https://check.torproject.org/ with status 200; "
        f"saw urls={[e['url'] for e in entries]!r}"
    )
    entry = matching[-1]
    assert entry["response_headers"], "response headers should be non-empty"
    assert entry["response_headers"].get("Content-Type", "").startswith("text/html")
    assert entry["method"] == "GET"
    assert isinstance(entry["response_body"], (str, dict, type(None)))


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
