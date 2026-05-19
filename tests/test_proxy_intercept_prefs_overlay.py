"""Unit tests for the ``proxy-intercept`` prefs overlay and integration."""

from __future__ import annotations

from pathlib import Path

import pytest

from torbrowser_driver import DEFAULT_CAPABILITIES, DriverConfig, PathPolicy
from torbrowser_driver.browser_process import (
    _load_bearing_prefs,
    _proxy_intercept_prefs_overlay,
)


_REPLACED_KEYS = {
    "network.proxy.type",
    "network.proxy.socks",
    "network.proxy.socks_port",
    "network.proxy.socks_remote_dns",
    "network.security.ports.banned.override",
    "network.dns.disabled",
    "network.proxy.allow_hijacking_localhost",
    "extensions.torbutton.use_nontor_proxy",
}

_NEW_KEYS = {
    "network.proxy.http",
    "network.proxy.http_port",
    "network.proxy.ssl",
    "network.proxy.ssl_port",
    "network.proxy.share_proxy_settings",
    "network.proxy.no_proxies_on",
}


@pytest.fixture()
def base_config(tmp_path: Path, fake_tbb_layout: Path) -> DriverConfig:
    policy = PathPolicy.from_config(output_dir=tmp_path / "out", cwd=tmp_path)
    return DriverConfig(
        tbb_root=fake_tbb_layout,
        path_policy=policy,
        socks_port=9259,
        control_port=9260,
        intercept_port=9261,
    )


def test_overlay_contains_all_replaced_and_new_keys(base_config: DriverConfig) -> None:
    overlay = _proxy_intercept_prefs_overlay(base_config)
    assert _REPLACED_KEYS <= overlay.keys()
    assert _NEW_KEYS <= overlay.keys()


def test_overlay_values(base_config: DriverConfig) -> None:
    overlay = _proxy_intercept_prefs_overlay(base_config)
    assert overlay["network.proxy.type"] == 1
    assert overlay["network.proxy.socks"] == ""
    assert overlay["network.proxy.socks_port"] == 0
    assert overlay["network.proxy.socks_remote_dns"] is False
    assert overlay["network.security.ports.banned.override"] == "9259,9260,9261"
    assert overlay["network.proxy.http"] == "127.0.0.1"
    assert overlay["network.proxy.http_port"] == 9261
    assert overlay["network.proxy.ssl"] == "127.0.0.1"
    assert overlay["network.proxy.ssl_port"] == 9261
    assert overlay["network.proxy.share_proxy_settings"] is True
    assert overlay["network.proxy.no_proxies_on"] == ""
    assert overlay["network.dns.disabled"] is False
    assert overlay["network.proxy.allow_hijacking_localhost"] is False
    assert overlay["extensions.torbutton.use_nontor_proxy"] is True


def test_load_bearing_prefs_without_cap_unchanged(base_config: DriverConfig) -> None:
    prefs = _load_bearing_prefs(base_config)
    # Default wiring: SOCKS still points at the bundled tor.
    assert prefs["network.proxy.socks"] == "127.0.0.1"
    assert prefs["network.proxy.socks_port"] == base_config.socks_port
    # Intercept-only keys must not appear.
    for key in _NEW_KEYS - {"network.proxy.no_proxies_on"}:
        assert key not in prefs, f"{key!r} leaked into base prefs"


def test_load_bearing_prefs_with_cap_merges_overlay(base_config: DriverConfig) -> None:
    config = type(base_config)(
        **{
            **base_config.__dict__,
            "enabled_caps": DEFAULT_CAPABILITIES | {"proxy-intercept"},
        }
    )
    prefs = _load_bearing_prefs(config)
    overlay = _proxy_intercept_prefs_overlay(config)
    for key, value in overlay.items():
        assert prefs[key] == value, f"overlay {key!r} not applied"
    # Non-overridden defaults still present.
    assert prefs["app.update.enabled"] is False
    assert "browser.download.folderList" in prefs
    assert "webdriver.load.strategy" in prefs


def test_load_bearing_prefs_overlay_widens_banned_ports(
    base_config: DriverConfig,
) -> None:
    config = type(base_config)(
        **{
            **base_config.__dict__,
            "enabled_caps": DEFAULT_CAPABILITIES | {"proxy-intercept"},
        }
    )
    prefs = _load_bearing_prefs(config)
    banned = prefs["network.security.ports.banned.override"]
    parts = set(banned.split(","))
    assert parts == {"9259", "9260", "9261"}
