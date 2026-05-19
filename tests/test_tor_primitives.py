"""Tests for the ``tor`` capability driver primitives."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from stem import ControllerError, Signal

from tests.conftest import _FakeConfig
from torbrowser_driver import PathPolicy, TorBrowserDriver, TorBrowserDriverError


@pytest.fixture
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
    assert result["count"] == 2
    assert result["total"] == 2
    assert result["truncated"] is False
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


def test_tor_circuit_status_limit(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.return_value = "1 BUILT\n2 BUILT\n3 BUILT"
    result = drv.tor_circuit_status(limit=2)
    assert [c["id"] for c in result["circuits"]] == ["1", "2"]
    assert result["count"] == 2
    assert result["total"] == 3
    assert result["truncated"] is True


def test_tor_stream_status_parsing(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.return_value = (
        "12 SUCCEEDED 7 example.test:443\n"
        "13 NEW 0 other.test:80"
    )
    result = drv.tor_stream_status()
    assert result["count"] == 2
    assert result["total"] == 2
    assert result["truncated"] is False
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
    assert result["count"] == 2
    assert result["total"] == 2
    assert result["truncated"] is False
    assert result["guards"][0]["nickname"] == "Alice"
    assert result["guards"][0]["fingerprint"] == "AAAA"
    assert result["guards"][0]["status"] == "up"
    assert result["guards"][1]["nickname"] is None
    assert result["guards"][1]["fingerprint"] == "BBBB"


def test_tor_get_info_allowlist(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.side_effect = lambda key: f"value-of-{key}"
    result = drv.tor_get_info(["version", "uptime"])
    assert result == {
        "info": {"version": "value-of-version", "uptime": "value-of-uptime"}
    }


def test_tor_get_info_file_output(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.controller.get_info.side_effect = lambda key: f"value-of-{key}"
    result = drv.tor_get_info(["version"], filename="tor-info.json")
    path = Path(result["path"])
    assert path == (policy.output_dir / "tor-info.json").resolve()
    assert result["keys"] == ["version"]
    assert "info" not in result
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "info": {"version": "value-of-version"}
    }


def test_tor_get_info_large_inline_returns_summary(drv: TorBrowserDriver) -> None:
    drv.controller.get_info.return_value = "x" * 600_000
    result = drv.tor_get_info(["ns/all"])
    assert result["truncated"] is True
    assert result["bytes"] > result["inline_cap"]
    assert "info" not in result


def test_tor_get_info_rejects_unknown_key(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        drv.tor_get_info(["arbitrary/key"])


def test_tor_resolve_not_implemented(drv: TorBrowserDriver) -> None:
    with pytest.raises(NotImplementedError):
        drv.tor_resolve("example.test")
