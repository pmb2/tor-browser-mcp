"""Tests for browser_process behaviour specific to the helper-extension cap.

Covers the prefs delta toggled on by the cap and the profile-sideload
step that drops the prepacked XPI under ``<profile>/extensions/``.
"""

from __future__ import annotations

from pathlib import Path

from torbrowser_driver import DEFAULT_CAPABILITIES, DriverConfig, PathPolicy
from torbrowser_driver.browser_process import _load_bearing_prefs


def _config(fake_tbb_layout: Path, policy: PathPolicy, *, with_helper: bool) -> DriverConfig:
    caps = DEFAULT_CAPABILITIES.copy()
    if with_helper:
        caps = caps | {"helper-extension"}
    return DriverConfig(
        tbb_root=fake_tbb_layout,
        path_policy=policy,
        enabled_caps=caps,
    )


def test_helper_cap_off_omits_sideload_prefs(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    prefs = _load_bearing_prefs(_config(fake_tbb_layout, policy, with_helper=False))
    for key in (
        "extensions.autoDisableScopes",
        "extensions.enabledScopes",
        "xpinstall.signatures.required",
        "network.proxy.allow_hijacking_localhost",
    ):
        assert key not in prefs


def test_helper_cap_on_sets_sideload_prefs(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    prefs = _load_bearing_prefs(_config(fake_tbb_layout, policy, with_helper=True))
    assert prefs["extensions.autoDisableScopes"] == 0
    assert prefs["extensions.enabledScopes"] == 15
    assert prefs["xpinstall.signatures.required"] is False
    assert prefs["network.proxy.allow_hijacking_localhost"] is False
    assert prefs["network.proxy.no_proxies_on"] == "127.0.0.1,localhost"
