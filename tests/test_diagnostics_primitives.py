"""Tests for the ``diagnostics`` capability driver primitives."""

from __future__ import annotations

import platform
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from torbrowser_driver import DriverConfig, PathPolicy, TorBrowserDriver


class _FakeConfig(SimpleNamespace):
    pass


@pytest.fixture()
def policy(tmp_path: Path) -> PathPolicy:
    out = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    return PathPolicy.from_config(
        output_dir=out, cwd=work, allowed_roots=[work]
    )


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


def test_console_messages_supported(drv: TorBrowserDriver) -> None:
    drv.webdriver.get_log.return_value = [
        {"level": "INFO", "message": "a"},
        {"level": "WARNING", "message": "b"},
    ]
    result = drv.browser_console_messages()
    assert result["supported"] is True
    assert len(result["messages"]) == 2


def test_console_messages_level_filter(drv: TorBrowserDriver) -> None:
    drv.webdriver.get_log.return_value = [
        {"level": "INFO", "message": "a"},
        {"level": "WARNING", "message": "b"},
    ]
    result = drv.browser_console_messages(level="warning")
    assert [m["message"] for m in result["messages"]] == ["b"]


def test_console_messages_unsupported_fallback(drv: TorBrowserDriver) -> None:
    drv.webdriver.get_log.side_effect = RuntimeError("not supported")
    result = drv.browser_console_messages()
    assert result["supported"] is False
    assert result["messages"] == []
    assert "helper-extension" in result["note"]


def test_console_messages_writes_file(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.get_log.return_value = []
    result = drv.browser_console_messages(filename="console.json")
    assert Path(result["path"]) == (policy.output_dir / "console.json").resolve()
    assert result["supported"] is True


def _make_tbb_layout(root: Path) -> Path:
    browser = root / "Browser"
    browser.mkdir(parents=True)
    if platform.system() == "Windows":
        firefox = browser / "firefox.exe"
        tor = browser / "TorBrowser" / "Tor" / "tor.exe"
    else:
        firefox = browser / "firefox"
        tor = browser / "TorBrowser" / "Tor" / "tor"
    tor.parent.mkdir(parents=True)
    firefox.write_bytes(b"")
    tor.write_bytes(b"")
    return root


def test_get_config_snapshot(tmp_path: Path) -> None:
    tbb = _make_tbb_layout(tmp_path / "tbb")
    policy = PathPolicy.from_config(
        output_dir=tmp_path / "out",
        cwd=tmp_path,
        allowed_roots=[tmp_path / "extra"],
    )
    config = DriverConfig(tbb_root=tbb, path_policy=policy, headless=True)

    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = config
    instance.webdriver = MagicMock()
    instance.controller = None
    instance._closed = False
    instance._tor_process = None
    instance._session_dir = None
    instance._owns_session_dir = False
    instance._owns_tor_data_dir = False

    snap = instance.browser_get_config()
    assert snap["tbb_root"] == str(tbb)
    assert snap["headless"] is True
    assert snap["socks_port"] == 9250
    assert snap["control_port"] == 9251
    assert "core" in snap["enabled_caps"]
    assert snap["enabled_caps"] == sorted(snap["enabled_caps"])
    assert snap["output_dir"] == str(policy.output_dir)
    assert snap["allowed_roots"] == [str(p) for p in policy.allowed_roots]


def test_fingerprint_probe_returns_canned(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = {
        "navigator_webdriver": True,
        "user_agent": "Mozilla/5.0",
        "platform": "Win32",
        "language": "en-US",
        "languages": ["en-US"],
        "timezone": "UTC",
        "screen": {
            "width": 1000,
            "height": 800,
            "color_depth": 24,
            "device_pixel_ratio": 1,
        },
        "window_inner": {"width": 1000, "height": 800},
        "do_not_track": "1",
        "hardware_concurrency": 4,
        "plugins": [],
    }
    result = drv.browser_fingerprint_probe()
    assert result["navigator_webdriver"] is True
    assert result["timezone"] == "UTC"
    assert result["screen"]["width"] == 1000
