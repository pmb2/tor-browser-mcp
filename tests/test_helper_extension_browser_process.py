"""Tests for browser_process behaviour specific to the helper-extension cap.

Covers the prefs delta toggled on by the cap and the profile-sideload
step that drops the prepacked XPI under ``<profile>/extensions/``.
"""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from torbrowser_driver import DEFAULT_CAPABILITIES, DriverConfig, PathPolicy
from torbrowser_driver.browser_process import _load_bearing_prefs


def _fake_tbb_layout(root: Path) -> Path:
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


@pytest.fixture()
def fake_tbb(tmp_path: Path) -> Path:
    return _fake_tbb_layout(tmp_path / "tbb")


@pytest.fixture()
def policy(tmp_path: Path) -> PathPolicy:
    return PathPolicy.from_config(output_dir=tmp_path / "out", cwd=tmp_path)


def _config(fake_tbb: Path, policy: PathPolicy, *, with_helper: bool) -> DriverConfig:
    caps = DEFAULT_CAPABILITIES.copy()
    if with_helper:
        caps = caps | {"helper-extension"}
    return DriverConfig(
        tbb_root=fake_tbb,
        path_policy=policy,
        enabled_caps=caps,
    )


def test_helper_cap_off_omits_sideload_prefs(
    fake_tbb: Path, policy: PathPolicy
) -> None:
    prefs = _load_bearing_prefs(_config(fake_tbb, policy, with_helper=False))
    for key in (
        "extensions.autoDisableScopes",
        "extensions.enabledScopes",
        "xpinstall.signatures.required",
        "network.proxy.allow_hijacking_localhost",
    ):
        assert key not in prefs


def test_helper_cap_on_sets_sideload_prefs(
    fake_tbb: Path, policy: PathPolicy
) -> None:
    prefs = _load_bearing_prefs(_config(fake_tbb, policy, with_helper=True))
    assert prefs["extensions.autoDisableScopes"] == 0
    assert prefs["extensions.enabledScopes"] == 15
    assert prefs["xpinstall.signatures.required"] is False
    assert prefs["network.proxy.allow_hijacking_localhost"] is False
    assert prefs["network.proxy.no_proxies_on"] == "127.0.0.1,localhost"



