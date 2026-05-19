"""Tests for the ``tor`` capability driver primitives."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from stem import ControllerError, Signal

from torbrowser_driver import PathPolicy, TorBrowserDriver, TorBrowserDriverError

from tests.conftest import _FakeConfig


@pytest.fixture()
def drv(drv: TorBrowserDriver, policy: PathPolicy) -> TorBrowserDriver:
    drv.config = _FakeConfig(  # type: ignore[assignment]
        path_policy=policy, socks_port=9250, control_port=9251
    )
    drv.controller = MagicMock(name="controller")
    return drv


def test_require_controller_raises_when_missing(policy: PathPolicy) -> None:
    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = _FakeConfig(  # type: ignore[assignment]
        path_policy=policy, socks_port=9250, control_port=9251
    )
    instance.webdriver = MagicMock()
    instance.controller = None
    with pytest.raises(TorBrowserDriverError, match="controller not started"):
        instance.tor_new_identity(wait=False)


def test_tor_status_happy(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.side_effect = lambda key: {
        "status/bootstrap-phase": "NOTICE BOOTSTRAP PROGRESS=100",
        "status/circuit-established": "1",
    }[key]
    drv.controller.get_version.return_value = "0.4.8.10"
    drv.controller.is_alive.return_value = True

    result = drv.tor_status()
    assert result["running"] is True
    assert result["circuit_established"] is True
    assert result["socks_port"] == 9250
    assert result["control_port"] == 9251
    assert result["version"] == "0.4.8.10"


def test_tor_status_controller_error(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.side_effect = ControllerError("no")
    result = drv.tor_status()
    assert result["running"] is False
    assert "no" in result["error"]


def test_tor_new_identity_no_wait(drv: TorBrowserDriver) -> None:
    result = drv.tor_new_identity(wait=False)
    drv.controller.signal.assert_called_once_with(Signal.NEWNYM)
    assert result == {"signaled": True, "waited": None}


def test_tor_new_identity_with_wait(monkeypatch, drv: TorBrowserDriver) -> None:
    import torbrowser_driver._tor_primitives as tor_mod

    sleeps: list[float] = []
    monkeypatch.setattr(tor_mod.time, "sleep", lambda s: sleeps.append(s))
    result = drv.tor_new_identity(wait=True, post_signal_sleep=0.5)
    assert sleeps == [0.5]
    assert result == {"signaled": True, "waited": 0.5}


def test_tor_circuit_status_parsing(drv: TorBrowserDriver) -> None:
    raw = (
        "1 BUILT $AAAA~Alice,$BBBB~Bob,$CCCC~Carol "
        "BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2025-01-01T00:00:00.000000\n"
        "2 EXTENDED $DDDD~Dave BUILD_FLAGS=IS_INTERNAL PURPOSE=HS_CLIENT_INTRO TIME_CREATED=now"
    )
    drv.controller.get_info.return_value = raw
    result = drv.tor_circuit_status()
    assert len(result["circuits"]) == 2
    first = result["circuits"][0]
    assert first["id"] == "1"
    assert first["status"] == "BUILT"
    assert first["path"] == [
        {"fingerprint": "AAAA", "nickname": "Alice"},
        {"fingerprint": "BBBB", "nickname": "Bob"},
        {"fingerprint": "CCCC", "nickname": "Carol"},
    ]
    assert first["purpose"] == "GENERAL"
    assert "build_flags" not in first
    assert "time_created" not in first


def test_tor_circuit_status_verbose(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.return_value = (
        "1 BUILT $AAAA~Alice BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL "
        "TIME_CREATED=2025-01-01"
    )
    result = drv.tor_circuit_status(verbose=True)
    entry = result["circuits"][0]
    assert entry["build_flags"] == "NEED_CAPACITY"
    assert entry["time_created"] == "2025-01-01"


def test_tor_stream_status_parsing(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.return_value = (
        "12 SUCCEEDED 7 example.test:443\n"
        "13 NEW 0 other.test:80"
    )
    result = drv.tor_stream_status()
    assert result["streams"][0] == {
        "id": "12",
        "status": "SUCCEEDED",
        "circuit_id": "7",
        "target": "example.test:443",
    }
    assert result["streams"][1]["status"] == "NEW"


def test_tor_entry_guards_parsing(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.return_value = (
        "Alice=$AAAA up\n"
        "$BBBB never-connected"
    )
    result = drv.tor_entry_guards()
    assert result["guards"][0]["nickname"] == "Alice"
    assert result["guards"][0]["fingerprint"] == "AAAA"
    assert result["guards"][0]["status"] == "up"
    assert result["guards"][1]["nickname"] is None
    assert result["guards"][1]["fingerprint"] == "BBBB"


def test_tor_get_info_allowlist(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.side_effect = lambda key: f"value-of-{key}"
    result = drv.tor_get_info(["version", "uptime"])
    assert result == {"info": {"version": "value-of-version", "uptime": "value-of-uptime"}}


def test_tor_get_info_rejects_unknown_key(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        drv.tor_get_info(["arbitrary/key"])


def test_tor_resolve_not_implemented(drv: TorBrowserDriver) -> None:
    with pytest.raises(NotImplementedError):
        drv.tor_resolve("example.test")
