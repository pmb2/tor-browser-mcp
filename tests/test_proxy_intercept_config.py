"""DriverConfig validation for the ``intercept_port`` field."""

from __future__ import annotations

from pathlib import Path

import pytest

from torbrowser_driver import DriverConfig, DriverConfigError, PathPolicy


def test_intercept_port_defaults_to_9261(fake_tbb_layout: Path, policy: PathPolicy) -> None:
    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)
    assert config.intercept_port == 9261


def test_intercept_port_accepts_custom_value(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    config = DriverConfig(
        tbb_root=fake_tbb_layout, path_policy=policy, intercept_port=18080
    )
    assert config.intercept_port == 18080


def test_intercept_port_rejects_out_of_range(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy, intercept_port=0)
    with pytest.raises(DriverConfigError):
        DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy, intercept_port=70000)


def test_intercept_port_must_differ_from_socks_port(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout,
            path_policy=policy,
            socks_port=9250,
            control_port=9251,
            intercept_port=9250,
        )


def test_intercept_port_must_differ_from_control_port(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout,
            path_policy=policy,
            socks_port=9250,
            control_port=9251,
            intercept_port=9251,
        )


def test_intercept_port_must_differ_from_helper_bridge_port(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    with pytest.raises(DriverConfigError):
        DriverConfig(
            tbb_root=fake_tbb_layout,
            path_policy=policy,
            socks_port=9250,
            control_port=9251,
            helper_bridge_port=9258,
            intercept_port=9258,
        )


def test_intercept_port_helper_bridge_unset_does_not_constrain(
    fake_tbb_layout: Path, policy: PathPolicy
) -> None:
    config = DriverConfig(
        tbb_root=fake_tbb_layout,
        path_policy=policy,
        socks_port=9250,
        control_port=9251,
        helper_bridge_port=None,
        intercept_port=9261,
    )
    assert config.intercept_port == 9261
    assert config.helper_bridge_port is None
