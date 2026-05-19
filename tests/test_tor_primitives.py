"""Tests for the ``tor`` capability driver primitives."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from selenium.common.exceptions import WebDriverException
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
        "1 BUILT $AAAA~Alice BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2025-01-01"
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
    drv.controller.get_info.return_value = "12 SUCCEEDED 7 example.test:443\n13 NEW 0 other.test:80"
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
    drv.controller.get_info.return_value = "Alice=$AAAA up\n$BBBB never-connected"
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
    assert result == {"info": {"version": "value-of-version", "uptime": "value-of-uptime"}}


def test_tor_get_info_file_output(drv: TorBrowserDriver, policy: PathPolicy) -> None:
    drv.controller.get_info.side_effect = lambda key: f"value-of-{key}"
    result = drv.tor_get_info(["version"], filename="tor-info.json")
    path = Path(result["path"])
    assert path == (policy.output_dir / "tor-info.json").resolve()
    assert result["keys"] == ["version"]
    assert "info" not in result
    assert json.loads(path.read_text(encoding="utf-8")) == {"info": {"version": "value-of-version"}}


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


def _check_probe(
    *,
    on_text: str | None = None,
    off_text: str | None = None,
    headline: str = "",
    body_text: str = "",
    uri: str = "https://check.torproject.org/",
    title: str = "",
) -> dict[str, object]:
    return {
        "uri": uri,
        "title": title,
        "readyState": "complete",
        "onText": on_text,
        "offText": off_text,
        "headlineText": headline,
        "bodyText": body_text,
    }


def test_tor_check_identity_reports_headline_on_success(
    drv: TorBrowserDriver,
) -> None:
    probe = _check_probe(
        on_text="Congratulations. This browser is configured to use Tor.",
        body_text=(
            "Congratulations. This browser is configured to use Tor.\n"
            "Your IP address appears to be: 192.0.2.42\n"
            "Afrikaans, العربية, Azerbaijani, ..."
        ),
    )
    drv.webdriver.execute_script.return_value = probe

    result = drv.tor_check_identity(timeout=0.0, cache_buster=False)

    assert result["is_tor"] is True
    assert result["exit_ip"] == "192.0.2.42"
    assert result["headline"] == ("Congratulations. This browser is configured to use Tor.")
    assert result["body_excerpt"].startswith("Congratulations.")
    assert "Afrikaans" not in result["body_excerpt"]
    assert result["fetch_error"] is None


def test_tor_check_identity_reports_headline_on_not_tor(
    drv: TorBrowserDriver,
) -> None:
    probe = _check_probe(
        off_text="Sorry. You are not using Tor.",
        body_text=(
            "Sorry. You are not using Tor.\n"
            "Your IP address appears to be: 203.0.113.7\n"
            "Afrikaans, العربية, ..."
        ),
    )
    drv.webdriver.execute_script.return_value = probe

    result = drv.tor_check_identity(timeout=0.0, cache_buster=False)

    assert result["is_tor"] is False
    assert result["exit_ip"] is None
    assert result["headline"] == "Sorry. You are not using Tor."
    assert result["body_excerpt"].startswith("Sorry.")
    assert "Afrikaans" not in result["body_excerpt"]
    assert result["fetch_error"] is None


def test_tor_check_identity_flags_502_as_fetch_error(monkeypatch, drv: TorBrowserDriver) -> None:
    import torbrowser_driver._tor_primitives as tor_mod

    monkeypatch.setattr(tor_mod.time, "sleep", lambda _s: None)
    probe = _check_probe(
        title="502 Bad Gateway",
        headline="502 Bad Gateway",
        body_text="502 Bad Gateway\nconnection closed",
    )
    drv.webdriver.execute_script.return_value = probe

    result = drv.tor_check_identity(timeout=0.05, cache_buster=False)

    assert result["is_tor"] is None
    assert result["exit_ip"] is None
    assert result["fetch_error"] is not None
    assert "502" in result["fetch_error"]
    assert "502" in result["body_excerpt"]


def test_tor_check_identity_flags_neterror_page(monkeypatch, drv: TorBrowserDriver) -> None:
    import torbrowser_driver._tor_primitives as tor_mod

    monkeypatch.setattr(tor_mod.time, "sleep", lambda _s: None)
    probe = _check_probe(
        uri="about:neterror?e=proxyConnectFailure&u=https%3A//check.torproject.org/",
        title="Problem loading page",
        body_text="Unable to connect",
    )
    drv.webdriver.execute_script.return_value = probe

    result = drv.tor_check_identity(timeout=0.05, cache_buster=False)

    assert result["is_tor"] is None
    assert result["fetch_error"] is not None
    assert result["fetch_error"].startswith("firefox-error-page")


def test_tor_check_identity_flags_timeout_without_headline(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    import torbrowser_driver._tor_primitives as tor_mod

    monkeypatch.setattr(tor_mod.time, "sleep", lambda _s: None)
    drv.webdriver.execute_script.return_value = _check_probe(body_text="")

    result = drv.tor_check_identity(timeout=0.05, cache_buster=False)

    assert result["is_tor"] is None
    assert result["fetch_error"] == "blank-document"


def test_tor_check_identity_handles_navigation_failure(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.get.side_effect = WebDriverException("dns failure")

    result = drv.tor_check_identity(timeout=0.0, cache_buster=False)

    assert result["is_tor"] is None
    assert result["exit_ip"] is None
    assert result["fetch_error"] is not None
    assert result["fetch_error"].startswith("navigation-failed")
    assert result["body_excerpt"] == ""
    assert drv.webdriver.execute_script.call_count == 0


def test_tor_check_identity_cache_buster_appends_query(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.execute_script.return_value = _check_probe(
        on_text="Congratulations. This browser is configured to use Tor.",
        body_text="Your IP address appears to be: 192.0.2.1",
    )

    drv.tor_check_identity(timeout=0.0, cache_buster=True)

    drv.webdriver.get.assert_called_once()
    called_url = drv.webdriver.get.call_args.args[0]
    assert called_url.startswith("https://check.torproject.org/?_=")
