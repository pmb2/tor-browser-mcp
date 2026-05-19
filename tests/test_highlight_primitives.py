"""Tests for the ``highlight`` capability driver primitives."""

from __future__ import annotations

from torbrowser_driver import TorBrowserDriver


def test_browser_highlight_applies_default_style(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = {"found": True}

    result = drv.browser_highlight("#login")
    assert result["highlighted"] is True
    assert result["selector"] == "#login"
    assert "outline" in result["applied"]
    assert result["applied"]["outline"] == "3px solid #ff00ff"

    args, _ = drv.webdriver.execute_script.call_args
    assert args[1] == "#login"
    assert args[2] == result["applied"]


def test_browser_highlight_custom_style(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = {"found": True}

    style = {"outline": "1px dashed red"}
    result = drv.browser_highlight(".thing", style=style)
    assert result == {
        "highlighted": True,
        "selector": ".thing",
        "applied": {"outline": "1px dashed red"},
    }
    args, _ = drv.webdriver.execute_script.call_args
    assert args[2] == {"outline": "1px dashed red"}


def test_browser_highlight_missing_element_returns_false(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.execute_script.return_value = {"found": False}

    result = drv.browser_highlight("#nope")
    assert result == {"highlighted": False, "selector": "#nope"}


def test_browser_highlight_handles_null_script_result(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.execute_script.return_value = None
    result = drv.browser_highlight("#nope")
    assert result == {"highlighted": False, "selector": "#nope"}


def test_browser_hide_highlight_specific_target(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = {"cleared": 1}

    result = drv.browser_hide_highlight("#login")
    assert result == {"cleared": 1}
    args, _ = drv.webdriver.execute_script.call_args
    # When target is given, the helper passes the selector as the second arg
    assert args[1] == "#login"


def test_browser_hide_highlight_walks_document_when_target_is_none(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.execute_script.return_value = {"cleared": 3}

    result = drv.browser_hide_highlight()
    assert result == {"cleared": 3}
    args, _ = drv.webdriver.execute_script.call_args
    # No selector argument was forwarded - only the JS source
    assert len(args) == 1
    assert "data-tbm-prior-style" in args[0]


def test_browser_hide_highlight_missing_default_zero(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = None
    assert drv.browser_hide_highlight("#nope") == {"cleared": 0}
