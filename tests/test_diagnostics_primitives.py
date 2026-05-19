"""Tests for the ``diagnostics`` capability driver primitives."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from torbrowser_driver import DriverConfig, PathPolicy, TorBrowserDriver


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


def test_get_config_snapshot(tmp_path: Path, fake_tbb_layout: Path) -> None:
    policy = PathPolicy.from_config(
        output_dir=tmp_path / "out",
        cwd=tmp_path,
        allowed_roots=[tmp_path / "extra"],
    )
    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy, headless=True)

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
    assert snap["tbb_root"] == str(fake_tbb_layout)
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
