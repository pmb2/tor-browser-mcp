"""Integration smoke tests for the optional capability mixins.

Exercises ``vision``, ``highlight``, ``tor-routing``, and ``unsafe``
against a real Tor Browser + bundled tor. Opt-in: skipped unless
``TBB_ROOT`` points at an extracted Tor Browser bundle. Set
``GECKODRIVER_PATH`` if geckodriver is not on ``PATH``. Run with
``pytest -m integration``.

Uses control/SOCKS ports 9254/9255 so it does not collide with the
existing driver-level smoke (9250/9251) or the MCP wire smoke
(9252/9253).
"""

from __future__ import annotations

import base64
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


SOCKS_PORT = 9254
CONTROL_PORT = 9255

OPTIONAL_CAPS_UNDER_TEST: frozenset[str] = frozenset(
    {"vision", "highlight", "tor-routing", "unsafe", "pdf", "http-over-tor"}
)


def _data_url(html: str) -> str:
    """Return a base64-encoded ``data:text/html`` URL for ``html``."""

    encoded = base64.b64encode(html.encode("utf-8")).decode("ascii")
    return f"data:text/html;base64,{encoded}"


def _conf_to_list(value: object) -> list[str]:
    """Normalise ``Controller.get_conf`` results to a list of strings.

    ``get_conf`` returns ``str`` for single-valued entries and ``list[str]``
    for multi-value ones, depending on the option and stem version. Tests
    consume the list shape uniformly.
    """

    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    text = str(value)
    if not text:
        return []
    return [text]


@pytest.fixture(scope="module")
def drv(
    tbb_root: Path,
    geckodriver_path: Path | None,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[TorBrowserDriver]:
    """Boot one Tor Browser session shared by all optional-cap tests."""

    base = tmp_path_factory.mktemp("optional-caps-smoke")
    policy = PathPolicy.from_config(output_dir=base / "out", cwd=base)
    config = DriverConfig(
        tbb_root=tbb_root,
        path_policy=policy,
        geckodriver_path=geckodriver_path,
        headless=False,
        socks_port=SOCKS_PORT,
        control_port=CONTROL_PORT,
        enabled_caps=DEFAULT_CAPABILITIES | OPTIONAL_CAPS_UNDER_TEST,
    )

    with TorBrowserDriver(config) as driver:
        yield driver


def test_vision_primitives_live(drv: TorBrowserDriver) -> None:
    """Exercise vision-cap input primitives against a real button page."""

    html = """
    <!doctype html>
    <html><head><meta charset="utf-8"><title>vision</title>
    <style>
      html, body { margin: 0; padding: 0; }
      body { min-height: 2000px; }
      #btn {
        position: absolute;
        left: 50px;
        top: 50px;
        width: 100px;
        height: 40px;
      }
    </style></head>
    <body><button id="btn" onclick="this.dataset.clicked='1'">x</button></body>
    </html>
    """
    drv.browser_navigate(url=_data_url(html))

    resized = drv.browser_resize(width=800, height=600)
    assert resized == {"width": 800, "height": 600}

    live_size = drv.webdriver.get_window_size()
    assert abs(int(live_size["width"]) - 800) <= 50
    assert abs(int(live_size["height"]) - 600) <= 50

    drv.browser_mouse_click_xy(x=100, y=70)

    clicked = drv.webdriver.execute_script(
        "return document.getElementById('btn').dataset.clicked;"
    )
    assert clicked == "1"

    drv.webdriver.execute_script("window.scrollTo(0, 0);")
    drv.browser_mouse_wheel(delta_x=0, delta_y=200)
    scroll_y = drv.webdriver.execute_script("return window.scrollY;")
    assert isinstance(scroll_y, (int, float))
    assert scroll_y > 0


def test_highlight_primitives_live(drv: TorBrowserDriver) -> None:
    """Exercise highlight-cap overlay/restore primitives on a real DOM."""

    html = """
    <!doctype html>
    <html><head><meta charset="utf-8"><title>highlight</title></head>
    <body>
      <button id="x">hi</button>
      <span id="y">other</span>
    </body></html>
    """
    drv.browser_navigate(url=_data_url(html))

    applied = drv.browser_highlight(target="#x")
    assert applied["highlighted"] is True
    assert applied["selector"] == "#x"

    prior_attr = drv.webdriver.execute_script(
        "return document.getElementById('x').getAttribute('data-tbm-prior-style');"
    )
    assert prior_attr is not None

    outline = drv.webdriver.execute_script(
        "return getComputedStyle(document.getElementById('x')).outline;"
    )
    assert isinstance(outline, str) and outline.strip() != ""

    missing = drv.browser_highlight(target="#does-not-exist")
    assert missing == {"highlighted": False, "selector": "#does-not-exist"}

    cleared_one = drv.browser_hide_highlight(target="#x")
    assert cleared_one == {"cleared": 1}

    prior_after = drv.webdriver.execute_script(
        "return document.getElementById('x').getAttribute('data-tbm-prior-style');"
    )
    assert prior_after is None

    drv.browser_highlight(target="#x")
    drv.browser_highlight(target="#y")
    cleared_all = drv.browser_hide_highlight()
    assert cleared_all == {"cleared": 2}


def test_tor_routing_primitives_live(drv: TorBrowserDriver) -> None:
    """Exercise tor-routing-cap SETCONF/RESETCONF round-trips via stem."""

    ctrl = drv.controller
    assert ctrl is not None

    saved_exit = ctrl.get_conf("ExitNodes", "")
    saved_strict = ctrl.get_conf("StrictNodes", "0")

    try:
        country_result = drv.tor_set_exit_country(country_code="de", strict=False)
        assert country_result["exit_country"] == "DE"
        assert country_result["strict"] is False
        assert "previous" in country_result
        assert "ExitNodes" in country_result["previous"]

        exit_nodes_now = _conf_to_list(ctrl.get_conf("ExitNodes"))
        assert exit_nodes_now == ["{DE}"]

        nick_result = drv.tor_set_exit_nodes(
            nodes=["BogonRelayName"], strict=False
        )
        assert nick_result["exit_nodes"] == ["BogonRelayName"]

        exit_nodes_now = _conf_to_list(ctrl.get_conf("ExitNodes"))
        assert exit_nodes_now == ["BogonRelayName"]

        fake_fp = "a" * 40
        fp_result = drv.tor_set_exit_nodes(nodes=[fake_fp])
        assert fp_result["exit_nodes"] == ["$" + fake_fp.upper()]

        cleared = drv.tor_clear_exit_policy()
        assert cleared == {
            "cleared": [
                "ExitNodes",
                "StrictNodes",
                "ExcludeExitNodes",
                "EntryNodes",
                "ExcludeNodes",
            ]
        }
        post_clear = _conf_to_list(ctrl.get_conf("ExitNodes", ""))
        assert post_clear in ([], [""])

        with pytest.raises(ValueError):
            drv.tor_set_exit_country(country_code="usa")
        with pytest.raises(ValueError):
            drv.tor_set_exit_nodes(nodes=["not a valid token!"])
    finally:
        try:
            drv.tor_clear_exit_policy()
        except Exception:
            pass
        # Best-effort restore of the prior pinning, if any was set.
        try:
            if saved_exit:
                if isinstance(saved_exit, list):
                    ctrl.set_conf("ExitNodes", ",".join(saved_exit))
                else:
                    ctrl.set_conf("ExitNodes", str(saved_exit))
            if saved_strict and str(saved_strict) not in ("0", ""):
                ctrl.set_conf("StrictNodes", str(saved_strict))
        except Exception:
            pass


def test_unsafe_primitives_live(drv: TorBrowserDriver) -> None:
    """Exercise unsafe-cap RCE-equivalent primitives against real handles."""

    nav = drv.browser_navigate(url="about:blank")
    assert nav["url"].startswith("about:")

    py_result = drv.browser_run_python_unsafe(
        code="print('hi'); answer = 42"
    )
    assert py_result["stdout"] == "hi\n"
    assert py_result["globals"]["answer"] == "42"
    expected_scope = {
        "driver",
        "webdriver",
        "controller",
        "config",
        "path_policy",
        "output_dir",
    }
    assert expected_scope.issubset(py_result["globals"].keys())

    tor_result = drv.tor_control_command_unsafe(command="GETINFO version")
    assert tor_result["is_ok"] is True
    assert "version=" in tor_result["raw"]

    href = drv.webdriver.execute_script("return document.location.href;")
    assert isinstance(href, str)
    assert href.startswith("about:blank")

    chrome_result = drv.browser_chrome_evaluate_unsafe(
        script="return Services.appinfo.name;"
    )
    chrome_value = chrome_result["result"]
    assert isinstance(chrome_value, str) and chrome_value, (
        f"Services.appinfo.name returned an unexpected shape: {chrome_value!r}"
    )

    href_after = drv.webdriver.execute_script("return document.location.href;")
    assert isinstance(href_after, str)
    assert href_after.startswith("about:blank")


def test_pdf_primitives_live(drv: TorBrowserDriver) -> None:
    """Exercise the pdf-cap save against a real ``data:`` page.

    Skips with a clear diagnostic if Tor Browser's Firefox build does not
    expose a working ``print_page`` pipeline, which is the documented
    fall-through for the capability.
    """

    html = """
    <!doctype html>
    <html><head><meta charset="utf-8"><title>pdf-smoke</title></head>
    <body>
      <h1>Printable Heading</h1>
      <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
      <p>Second paragraph for layout bulk.</p>
    </body></html>
    """
    drv.browser_navigate(url=_data_url(html))

    try:
        result = drv.browser_pdf_save()
    except Exception as exc:
        pytest.skip(
            f"WebDriver.print_page failed against this Tor Browser build: "
            f"{exc!r}"
        )

    written = Path(result["path"])
    assert written.is_file()
    assert result["bytes"] > 1024, (
        f"PDF unexpectedly small ({result['bytes']} bytes); "
        f"print_page may be returning a stub"
    )
    with open(written, "rb") as fh:
        magic = fh.read(5)
    assert magic == b"%PDF-", (
        f"output at {written} does not start with %PDF- magic: {magic!r}"
    )


def test_http_over_tor_primitives_live(drv: TorBrowserDriver) -> None:
    """Exercise the http-over-tor primitives through the bundled tor."""

    result = drv.tor_http_request(
        method="GET",
        url="https://check.torproject.org/",
        timeout=60.0,
    )
    assert result["status"] == 200
    body = result.get("body")
    assert isinstance(body, str) and body, (
        f"expected textual body, got keys={list(result.keys())!r}"
    )
    assert ("Congratulations" in body) or ("Sorry" in body), (
        f"check.torproject.org body did not contain the expected markers; "
        f"first 300 chars: {body[:300]!r}"
    )

    drv.browser_navigate(url="https://check.torproject.org/")
    second = drv.tor_http_request(
        method="GET",
        url="https://check.torproject.org/",
        use_browser_cookies=True,
        timeout=60.0,
    )
    assert second["status"] == 200


def test_http_over_tor_sequence_live(drv: TorBrowserDriver) -> None:
    """Run a two-step sequence against ``check.torproject.org``.

    Flaky in principle (depends on the check.torproject.org JSON endpoint
    staying reachable). Skips on transport-level failure rather than
    failing.
    """

    try:
        out = drv.tor_http_sequence(
            requests=[
                {"url": "https://check.torproject.org/", "timeout": 60.0},
                {"url": "https://check.torproject.org/api/ip", "timeout": 60.0},
            ]
        )
    except Exception as exc:
        pytest.skip(f"tor_http_sequence transport error: {exc!r}")

    assert len(out["results"]) == 2
    statuses = [r["status"] for r in out["results"]]
    assert statuses[0] == 200, f"unexpected first-hop status: {statuses!r}"
    assert isinstance(out["final_cookie_jar"], dict)
