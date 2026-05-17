"""Tests for the ``vision`` capability driver primitives."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from selenium.webdriver.common.actions.mouse_button import MouseButton

from torbrowser_driver import PathPolicy, TorBrowserDriver


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
    instance.config = _FakeConfig(path_policy=policy)  # type: ignore[assignment]
    instance.webdriver = MagicMock(name="webdriver")
    instance.controller = None
    instance._closed = False
    instance._tor_process = None
    instance._session_dir = None
    instance._owns_session_dir = False
    instance._owns_tor_data_dir = False
    return instance


def _make_action_chain_mock(monkeypatch, recorder: list[tuple[str, tuple, dict]]):
    """Patch ActionChains in the vision module with a recording double."""

    import torbrowser_driver._vision_primitives as vision_mod

    chain = MagicMock(name="ActionChainsInstance")
    pointer_action = MagicMock(name="pointer_action")
    wheel_action = MagicMock(name="wheel_action")
    chain.w3c_actions.pointer_action = pointer_action
    chain.w3c_actions.wheel_action = wheel_action

    def _track(name):
        def _impl(*args, **kwargs):
            recorder.append((name, args, kwargs))
            return chain
        return _impl

    for method in (
        "move_to_location",
        "pointer_down",
        "pointer_up",
        "pause",
    ):
        setattr(pointer_action, method, _track(method))
    chain.scroll_by_amount.side_effect = _track("scroll_by_amount")
    chain.perform.side_effect = _track("perform")

    factory = MagicMock(return_value=chain)
    monkeypatch.setattr(vision_mod, "ActionChains", factory)
    return factory, chain


def test_browser_mouse_move_xy_calls_move_to_location(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    result = drv.browser_mouse_move_xy(120, 240)
    assert result == {"x": 120, "y": 240}
    assert ("move_to_location", (120, 240), {}) in rec
    assert any(name == "perform" for name, _, _ in rec)


def test_browser_mouse_click_xy_single_left(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    result = drv.browser_mouse_click_xy(10, 20)
    assert result == {"x": 10, "y": 20, "button": "left", "clicks": 1}

    names = [name for name, _, _ in rec]
    assert names[0] == "move_to_location"
    # one down + one up + perform
    assert names.count("pointer_down") == 1
    assert names.count("pointer_up") == 1
    down_call = next(call for call in rec if call[0] == "pointer_down")
    assert down_call[1] == (MouseButton.LEFT,)


def test_browser_mouse_click_xy_double_uses_two_down_up_pairs(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    drv.browser_mouse_click_xy(5, 6, click_count=2)
    names = [name for name, _, _ in rec]
    assert names.count("pointer_down") == 2
    assert names.count("pointer_up") == 2


def test_browser_mouse_click_xy_triple_with_delay(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    drv.browser_mouse_click_xy(0, 0, click_count=3, delay=0.05)
    names = [name for name, _, _ in rec]
    assert names.count("pointer_down") == 3
    assert names.count("pointer_up") == 3
    assert names.count("pause") == 2


def test_browser_mouse_click_xy_right_button(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    drv.browser_mouse_click_xy(1, 2, button="right")
    down_call = next(call for call in rec if call[0] == "pointer_down")
    assert down_call[1] == (MouseButton.RIGHT,)


def test_browser_mouse_click_xy_middle_button(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    drv.browser_mouse_click_xy(1, 2, button="MIDDLE")
    down_call = next(call for call in rec if call[0] == "pointer_down")
    assert down_call[1] == (MouseButton.MIDDLE,)


def test_browser_mouse_click_xy_rejects_invalid_button(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    _make_action_chain_mock(monkeypatch, [])
    with pytest.raises(ValueError, match="unsupported button"):
        drv.browser_mouse_click_xy(0, 0, button="thumb")


def test_browser_mouse_down_holds_button(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    result = drv.browser_mouse_down(7, 8, button="left")
    assert result == {"x": 7, "y": 8, "button": "left"}
    names = [name for name, _, _ in rec]
    assert "pointer_down" in names
    assert "pointer_up" not in names


def test_browser_mouse_up_releases_button(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    result = drv.browser_mouse_up(9, 10, button="right")
    assert result == {"x": 9, "y": 10, "button": "right"}
    names = [name for name, _, _ in rec]
    assert "pointer_up" in names
    assert "pointer_down" not in names


def test_browser_mouse_drag_xy_sequence(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    result = drv.browser_mouse_drag_xy(1, 2, 30, 40)
    assert result == {
        "start_x": 1,
        "start_y": 2,
        "end_x": 30,
        "end_y": 40,
        "button": "left",
    }
    names = [name for name, _, _ in rec]
    assert names[:5] == [
        "move_to_location",
        "pointer_down",
        "move_to_location",
        "pointer_up",
        "perform",
    ]
    moves = [call for call in rec if call[0] == "move_to_location"]
    assert moves[0][1] == (1, 2)
    assert moves[1][1] == (30, 40)


def test_browser_mouse_wheel_calls_scroll_by_amount(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    rec: list[tuple[str, tuple, dict]] = []
    _make_action_chain_mock(monkeypatch, rec)

    result = drv.browser_mouse_wheel(-50, 100)
    assert result == {"delta_x": -50, "delta_y": 100}
    assert ("scroll_by_amount", (-50, 100), {}) in rec


def test_browser_resize_calls_set_window_size(drv: TorBrowserDriver) -> None:
    result = drv.browser_resize(1280, 720)
    drv.webdriver.set_window_size.assert_called_once_with(1280, 720)
    assert result == {"width": 1280, "height": 720}
