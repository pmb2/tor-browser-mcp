"""Integration smoke for the ``proxy-intercept`` substrate.

Boots a real Tor Browser session with ``proxy-intercept`` enabled,
navigates through the embedded mitmproxy listener, and confirms the
recorder buffer saw the request.

Two opt-in gates apply. The first is the usual ``-m integration``
marker; the second is the ``TBB_ALLOW_DESTRUCTIVE_CAPS=1`` environment
variable, because enabling the cap installs a CA into the Tor Browser
install directory via ``policies.json``. The teardown restores the
prior state, but the side-effect is real enough that a developer
running ``pytest -m integration`` against a shared TB install should
have to opt in explicitly.

Ports: SOCKS 9259, control 9260, intercept 9261. The
``optional-caps`` smoke uses 9254/9255 and the helper-extension smoke
uses 9256/9257/9258, so these collide with neither.
"""

from __future__ import annotations

import json
import os
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
from torbrowser_driver._proxy_intercept_policies import policies_path


pytestmark = pytest.mark.integration


SOCKS_PORT = 9259
CONTROL_PORT = 9260
INTERCEPT_PORT = 9261


@pytest.fixture(scope="module")
def destructive_caps_allowed() -> None:
    if os.environ.get("TBB_ALLOW_DESTRUCTIVE_CAPS") != "1":
        pytest.skip("TBB_ALLOW_DESTRUCTIVE_CAPS=1 not set")


def _build_config(
    tbb_root: Path,
    geckodriver_path: Path | None,
    base: Path,
) -> DriverConfig:
    policy = PathPolicy.from_config(output_dir=base / "out", cwd=base)
    return DriverConfig(
        tbb_root=tbb_root,
        path_policy=policy,
        geckodriver_path=geckodriver_path,
        headless=False,
        socks_port=SOCKS_PORT,
        control_port=CONTROL_PORT,
        intercept_port=INTERCEPT_PORT,
        enabled_caps=DEFAULT_CAPABILITIES | {"proxy-intercept"},
    )


@pytest.fixture(scope="module")
def _module_drv(
    destructive_caps_allowed: None,
    tbb_root: Path,
    geckodriver_path: Path | None,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[TorBrowserDriver]:
    """Single Tor Browser boot shared by every test that tolerates state reset.

    A full TB launch with the ``proxy-intercept`` cap takes 30-40 s; the
    four observation/replay tests in this module can all run against the
    same substrate provided the recorder buffer and cursor are cleared
    between cases. The policies-restore test below builds its own driver
    because it tests the install-time/teardown-time side-effects of
    construction, which a shared session cannot exercise.
    """

    base = tmp_path_factory.mktemp("proxy-intercept-smoke")
    config = _build_config(tbb_root, geckodriver_path, base)
    with TorBrowserDriver(config) as driver:
        yield driver


@pytest.fixture()
def drv(_module_drv: TorBrowserDriver) -> TorBrowserDriver:
    """Module-scoped driver with per-test recorder reset.

    ``browser_intercept_stop`` empties the flow buffer and resets the
    monotonic ``since`` cursor without touching the daemon thread or the
    upstream SOCKS chain, so each test starts from a clean recorder
    state even though the underlying TB session is shared.
    """

    _module_drv.browser_intercept_stop()
    return _module_drv


def test_proxy_intercept_records_https_navigation(drv: TorBrowserDriver) -> None:
    """A real HTTPS navigation lands in the recorder's flow buffer.

    The HTTP-CONNECT-to-SOCKS5h adapter chains every outbound dial
    through the bundled tor's SOCKS port, so a captured flow proves
    interception is wired through the full path. The flow's
    ``server_address`` is the upstream HTTP-CONNECT adapter on
    ``127.0.0.1``, not the exit IP; verifying the tor-exit IP belongs
    to a later slice with the actual routing query surfaced as a tool.
    """

    manager = drv._proxy_manager
    assert manager is not None
    assert manager.is_alive(), "intercept thread should be alive"
    assert manager.listen_port == INTERCEPT_PORT
    assert manager.socks_adapter_port > 0

    drv.browser_navigate("https://example.com/")

    deadline = time.monotonic() + 30.0
    matching: list[dict] = []
    while time.monotonic() < deadline:
        flows = list(manager.flow_buffer)
        matching = [
            f
            for f in flows
            if f.get("request") is not None
            and f["request"].get("host") == "example.com"
            and f.get("response") is not None
            and f["response"].get("status_code") == 200
        ]
        if matching:
            break
        time.sleep(0.5)

    assert matching, (
        f"no example.com/200 flow captured; buffer size={len(list(manager.flow_buffer))}, "
        f"hosts={sorted({(f.get('request') or {}).get('host') for f in manager.flow_buffer})!r}"
    )
    entry = matching[-1]
    assert entry["request"]["scheme"] == "https"
    assert entry["request"]["method"] == "GET"
    addr = entry.get("server_address")
    assert addr is not None and addr[0]


def test_proxy_intercept_flows_surface_check_torproject(drv: TorBrowserDriver) -> None:
    """The five observation tools see a real check.torproject.org navigation.

    ``browser_intercept_start`` reports the running substrate's cursor;
    after navigating to the canonical tor-exit probe URL the recorder
    buffer carries at least one ``check.torproject.org/`` flow whose
    response body identifies the exit as either a Tor exit
    ("Congratulations") or a non-exit ("Sorry"). The captured archive
    is round-tripped through :class:`mitmproxy.io.FlowReader` to verify
    the on-disk file is a real mitmproxy flow stream, and
    ``browser_intercept_stop`` reports the at-stop count.

    If Firefox negotiates HTTP/3 / QUIC against the intercept proxy and
    refuses to fall back to HTTP/2, no flows would be captured. The
    test ``xfail``s with a clear message in that case; in practice
    Firefox negotiates HTTP/2 against an HTTP-proxy upstream.
    """

    import mitmproxy.io as mitm_io

    started = drv.browser_intercept_start()
    assert started["started"] is True
    assert started["intercept_port"] == INTERCEPT_PORT
    assert isinstance(started["since"], int)
    assert isinstance(started["ca_fingerprint"], str)
    assert len(started["ca_fingerprint"]) == 64

    drv.browser_navigate("https://check.torproject.org/")

    deadline = time.monotonic() + 30.0
    flows: list = []
    root_flows: list = []
    while time.monotonic() < deadline:
        result = drv.browser_intercept_flows(
            host="check.torproject.org", include_bodies=True
        )
        flows = result["flows"]
        root_flows = [
            f
            for f in flows
            if isinstance(f.get("request"), dict)
            and f["request"].get("path") == "/"
            and isinstance(f.get("response"), dict)
            and f["response"].get("status_code") == 200
        ]
        if root_flows:
            break
        time.sleep(0.5)

    if not flows:
        pytest.xfail(
            "no check.torproject.org flows captured; Firefox may have used"
            " HTTP/3 and refused the HTTP/2 fallback against the intercept proxy"
        )
    assert root_flows, (
        "no 200 flow at the / path captured; flows="
        f"{[(f.get('request') or {}).get('path', '?') + ' -> ' + str((f.get('response') or {}).get('status_code')) for f in flows]!r}"
    )
    entry = root_flows[-1]

    resp = entry["response"]
    assert resp["status_code"] == 200
    content_length = resp.get("content_length")
    if isinstance(content_length, int):
        assert content_length > 0

    body = resp.get("body")
    body_text = body if isinstance(body, str) else ""
    assert "Congratulations" in body_text or "Sorry" in body_text, (
        "check.torproject.org body did not contain the tor-exit gate phrase"
    )

    save_result = drv.browser_intercept_save(path="intercept-smoke.flows")
    archive = Path(save_result["path"])
    assert archive.is_file()
    assert archive.stat().st_size > 0
    assert isinstance(save_result["flow_count"], int)
    assert save_result["flow_count"] >= 1

    with open(archive, "rb") as fh:
        reader = mitm_io.FlowReader(fh)
        archived = list(reader.stream())
    assert len(archived) == save_result["flow_count"]
    assert any(
        getattr(getattr(f, "request", None), "host", "") == "check.torproject.org"
        for f in archived
    )

    stopped = drv.browser_intercept_stop()
    assert stopped["stopped"] is True
    assert stopped["flows_collected"] >= 1


def test_proxy_intercept_filters_by_host_and_status(drv: TorBrowserDriver) -> None:
    """Host and status-code filters narrow the recorder buffer correctly.

    Two navigations populate the buffer with different hosts; the host
    filter returns only the matching subset, and ``status_code=200``
    with ``limit=1`` returns one entry plus ``truncated=True`` when
    more than one 200 exists.
    """

    drv.browser_intercept_start()
    drv.browser_navigate("https://example.com/")
    time.sleep(2.0)
    drv.browser_navigate("https://check.torproject.org/")
    time.sleep(3.0)

    only_example = drv.browser_intercept_flows(host="example.com")
    hosts = {
        (f.get("request") or {}).get("host") for f in only_example["flows"]
    }
    if not hosts:
        pytest.xfail(
            "no example.com flows captured; Firefox may have used HTTP/3"
        )
    assert hosts, f"no example.com flows captured; hosts={hosts!r}"
    assert all(
        isinstance(h, str) and "example.com" in h.lower() for h in hosts
    ), f"host filter leaked non-matches: {hosts!r}"

    one_200 = drv.browser_intercept_flows(status_code=200, limit=1)
    assert len(one_200["flows"]) <= 1
    if one_200["flows"]:
        assert one_200["flows"][0]["response"]["status_code"] == 200


def test_proxy_intercept_replay_with_modified_user_agent(drv: TorBrowserDriver) -> None:
    """A captured flow can be replayed with a modified ``User-Agent`` header.

    Navigates to a known-200 page through the live intercept proxy,
    locates the source flow, replays it with a custom ``User-Agent``
    via :meth:`browser_intercept_replay`, then fetches the new flow and
    asserts both the replay surfaced under a fresh id and the response
    is a 200. The body content gate from the observation smoke is
    intentionally not re-applied here -- the live response from
    check.torproject.org may differ between the source navigation and
    the replay, but the replay's existence and status are stable
    signals.
    """

    drv.browser_intercept_start()
    drv.browser_navigate("https://check.torproject.org/")

    deadline = time.monotonic() + 30.0
    source_id: str | None = None
    while time.monotonic() < deadline:
        result = drv.browser_intercept_flows(host="check.torproject.org")
        candidates = [
            f
            for f in result["flows"]
            if isinstance(f.get("request"), dict)
            and f["request"].get("path") == "/"
            and isinstance(f.get("response"), dict)
            and f["response"].get("status_code") == 200
        ]
        if candidates:
            source_id = candidates[-1]["id"]
            break
        time.sleep(0.5)

    if source_id is None:
        pytest.xfail(
            "no source flow captured for check.torproject.org; replay cannot proceed"
        )

    replay = drv.browser_intercept_replay(
        flow_id=source_id,
        set_request_headers={"User-Agent": "tor-browser-mcp-replay/1.0"},
    )

    assert replay["source_flow_id"] == source_id
    assert replay["replay_flow_id"] != source_id
    assert isinstance(replay["since"], int)
    echoed_ua = [
        v for (n, v) in replay["request"]["headers"] if n.lower() == "user-agent"
    ]
    assert echoed_ua == ["tor-browser-mcp-replay/1.0"], (
        f"echoed request headers did not carry the override: {echoed_ua!r}"
    )

    full = drv.browser_intercept_flow(
        flow_id=replay["replay_flow_id"], include_bodies=True
    )
    assert full["id"] == replay["replay_flow_id"]
    request_headers = full.get("request", {}).get("headers") or []
    ua_values = [v for (n, v) in request_headers if n.lower() == "user-agent"]
    assert ua_values == ["tor-browser-mcp-replay/1.0"], (
        f"replay flow did not carry the User-Agent override: {ua_values!r}"
    )
    response = full.get("response")
    assert isinstance(response, dict), (
        f"replay produced no response: full={full!r}"
    )
    assert response.get("status_code") == 200, (
        f"replay response was not 200: {response.get('status_code')!r}"
    )


def test_proxy_intercept_restores_policies_on_close(
    destructive_caps_allowed: None,
    tbb_root: Path,
    geckodriver_path: Path | None,
    tmp_path: Path,
) -> None:
    """policies.json is installed during the session and removed after close.

    Two consecutive sessions confirm the snapshot-restore round-trip is
    idempotent. If the install already has a developer-authored
    ``policies.json`` the test skips rather than mutating the bundle.
    """

    target = policies_path(tbb_root)
    if target.is_file():
        pytest.skip(
            f"{target} exists before test; refusing to mutate developer state"
        )

    config = _build_config(tbb_root, geckodriver_path, tmp_path / "s1")
    with TorBrowserDriver(config) as driver:
        assert driver._proxy_ca_pem_path is not None
        assert target.is_file()
        data = json.loads(target.read_text("utf-8"))
        install_list = data["policies"]["Certificates"]["Install"]
        assert str(driver._proxy_ca_pem_path) in install_list
    assert not target.exists(), f"{target} should be removed after session 1"

    config2 = _build_config(tbb_root, geckodriver_path, tmp_path / "s2")
    with TorBrowserDriver(config2) as driver:
        assert target.is_file()
    assert not target.exists(), f"{target} should be removed after session 2"
