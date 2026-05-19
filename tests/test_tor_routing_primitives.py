"""Tests for the ``tor-routing`` capability driver primitives."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from torbrowser_driver import PathPolicy, TorBrowserDriver, TorBrowserDriverError

from tests.conftest import _FakeConfig


@pytest.fixture()
def drv(drv: TorBrowserDriver, policy: PathPolicy) -> TorBrowserDriver:
    drv.config = _FakeConfig(  # type: ignore[assignment]
        path_policy=policy, socks_port=9250, control_port=9251
    )
    controller = MagicMock(name="controller")
    controller.get_conf.side_effect = lambda key, default=None: {
        "ExitNodes": "",
        "StrictNodes": "0",
    }.get(key, default)
    drv.controller = controller
    return drv


def test_require_controller_raises_when_missing(policy: PathPolicy) -> None:
    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = _FakeConfig(  # type: ignore[assignment]
        path_policy=policy, socks_port=9250, control_port=9251
    )
    instance.webdriver = MagicMock()
    instance.controller = None
    with pytest.raises(TorBrowserDriverError, match="controller not started"):
        instance.tor_clear_exit_policy()


def test_tor_set_exit_country_uppercases_and_sets(drv: TorBrowserDriver) -> None:
    result = drv.tor_set_exit_country("us", strict=True)
    assert result["exit_country"] == "US"
    assert result["strict"] is True
    assert result["previous"] == {"ExitNodes": "", "StrictNodes": "0"}

    set_calls = drv.controller.set_conf.call_args_list
    assert ("ExitNodes", "{US}") in {c.args for c in set_calls}
    assert ("StrictNodes", "1") in {c.args for c in set_calls}


def test_tor_set_exit_country_strict_false_sends_zero(drv: TorBrowserDriver) -> None:
    drv.tor_set_exit_country("DE")
    set_calls = drv.controller.set_conf.call_args_list
    assert ("StrictNodes", "0") in {c.args for c in set_calls}


def test_tor_set_exit_country_rejects_three_letter(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError, match="invalid country code"):
        drv.tor_set_exit_country("USA")
    drv.controller.set_conf.assert_not_called()


def test_tor_set_exit_country_rejects_digits(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError, match="invalid country code"):
        drv.tor_set_exit_country("12")


def test_tor_set_exit_nodes_fingerprint(drv: TorBrowserDriver) -> None:
    fp = "A" * 40
    result = drv.tor_set_exit_nodes([fp, "$" + "b" * 40], strict=False)
    assert result["exit_nodes"] == ["$" + "A" * 40, "$" + "B" * 40]
    assert result["strict"] is False

    set_calls = {c.args for c in drv.controller.set_conf.call_args_list}
    assert ("ExitNodes", "$" + "A" * 40 + ",$" + "B" * 40) in set_calls
    assert ("StrictNodes", "0") in set_calls


def test_tor_set_exit_nodes_nickname(drv: TorBrowserDriver) -> None:
    result = drv.tor_set_exit_nodes(["Alice", "Bob123"])
    assert result["exit_nodes"] == ["Alice", "Bob123"]
    set_calls = {c.args for c in drv.controller.set_conf.call_args_list}
    assert ("ExitNodes", "Alice,Bob123") in set_calls


def test_tor_set_exit_nodes_rejects_malformed_fingerprint(
    drv: TorBrowserDriver,
) -> None:
    bad = "$" + "Z" * 40
    with pytest.raises(ValueError, match="invalid exit-node identifier"):
        drv.tor_set_exit_nodes([bad])
    drv.controller.set_conf.assert_not_called()


def test_tor_set_exit_nodes_rejects_empty_list(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError, match="at least one"):
        drv.tor_set_exit_nodes([])


def test_tor_set_exit_nodes_rejects_overlong_nickname(
    drv: TorBrowserDriver,
) -> None:
    too_long = "A" * 20
    with pytest.raises(ValueError, match="invalid exit-node identifier"):
        drv.tor_set_exit_nodes([too_long])


def test_tor_clear_exit_policy_resets_all_fields(drv: TorBrowserDriver) -> None:
    result = drv.tor_clear_exit_policy()
    drv.controller.reset_conf.assert_called_once_with(
        "ExitNodes",
        "StrictNodes",
        "ExcludeExitNodes",
        "EntryNodes",
        "ExcludeNodes",
    )
    assert result == {
        "cleared": [
            "ExitNodes",
            "StrictNodes",
            "ExcludeExitNodes",
            "EntryNodes",
            "ExcludeNodes",
        ]
    }


def test_tor_set_exit_country_carries_previous_values(drv: TorBrowserDriver) -> None:
    drv.controller.get_conf.side_effect = lambda key, default=None: {
        "ExitNodes": "{FR}",
        "StrictNodes": "1",
    }.get(key, default)
    result = drv.tor_set_exit_country("DE")
    assert result["previous"] == {"ExitNodes": "{FR}", "StrictNodes": "1"}
