"""Unit tests for DriverConfig validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from torbrowser_driver import DriverConfig, DriverConfigError, PathPolicy


def test_defaults_accept_valid_layout(fake_tbb_layout: Path, policy: PathPolicy) -> None:
    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)
    assert config.profile_mode == "ephemeral"
    assert config.headless is False
    assert config.socks_port == 9250
    assert config.control_port == 9251
    assert "core" in config.enabled_caps
    assert config.firefox_path.is_file()
    assert config.tor_path.is_file()


def test_rejects_bogus_tbb_root(tmp_path: Path, policy: PathPolicy) -> None:
    bogus = tmp_path / "not-a-bundle"
    bogus.mkdir()
    with pytest.raises(DriverConfigError):
        DriverConfig(tbb_root=bogus, path_policy=policy)


def test_persistent_requires_profile_path(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout,
            path_policy=policy,
            profile_mode="persistent",
        )


def test_rejects_overlapping_ports(fake_tbb_layout: Path, policy: PathPolicy) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout,
            path_policy=policy,
            socks_port=9250,
            control_port=9250,
        )


def test_rejects_missing_geckodriver(
    fake_tbb_layout: Path, policy: PathPolicy, tmp_path: Path
) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout,
            path_policy=policy,
            geckodriver_path=tmp_path / "no-such-geckodriver",
        )


def test_extra_prefs_default_is_empty(fake_tbb_layout: Path, policy: PathPolicy) -> None:
    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)
    assert dict(config.extra_prefs) == {}


def test_helper_bridge_port_defaults_to_none(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)
    assert config.helper_bridge_port is None
    assert config.helper_bridge_host == "127.0.0.1"


def test_helper_bridge_port_rejects_out_of_range(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout, path_policy=policy, helper_bridge_port=0
        )
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout, path_policy=policy, helper_bridge_port=70000
        )


def test_helper_bridge_port_must_differ_from_tor_ports(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout,
            path_policy=policy,
            socks_port=9250,
            control_port=9251,
            helper_bridge_port=9250,
        )
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout,
            path_policy=policy,
            socks_port=9250,
            control_port=9251,
            helper_bridge_port=9251,
        )


def test_helper_bridge_port_accepts_unique_value(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    config = DriverConfig(
        tbb_root=fake_tbb_layout,
        path_policy=policy,
        helper_bridge_port=9258,
    )
    assert config.helper_bridge_port == 9258


def test_allow_chrome_system_access_tracks_unsafe_cap(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    defaults = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)
    assert defaults.allow_chrome_system_access is False

    with_unsafe = DriverConfig(
        tbb_root=fake_tbb_layout,
        path_policy=policy,
        enabled_caps=defaults.enabled_caps | {"unsafe"},
    )
    assert with_unsafe.allow_chrome_system_access is True
