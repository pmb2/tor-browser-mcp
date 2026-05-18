"""Unit tests for the helper-extension install path.

The helper is installed by packing a per-session XPI (with the bridge
host, port and shared-secret token baked into ``config.json``) and
handing it to Marionette's ``install_addon`` with ``temporary=True``.
These tests cover the packer, the install/handshake flow, and the
teardown path without booting a real browser.
"""

from __future__ import annotations

import json
import threading
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from torbrowser_driver._helper_extension import (
    HELPER_EXTENSION_DIR,
    HELPER_EXTENSION_ID,
)
from torbrowser_driver._helper_extension_install import (
    install_helper,
    pack_helper_xpi,
    prepare_helper_install,
    uninstall_helper,
)
from torbrowser_driver.exceptions import BrowserLaunchError


class _FakeBridge:
    """Test double that mimics the surface install_helper relies on."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 12345,
        token: str = "fake-token",
        connect_immediately: bool = True,
        connect_but_reject: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.connect_event = threading.Event()
        self.connected = False
        self.close_called = False
        self._connect_immediately = connect_immediately
        self._connect_but_reject = connect_but_reject
        if connect_immediately:
            if not connect_but_reject:
                self.connected = True
            self.connect_event.set()

    def close(self) -> None:
        self.close_called = True
        self.connected = False
        self.connect_event.set()


class _FakeDriver:
    """Mimics the slice of TorBrowserDriver install_helper touches."""

    def __init__(self, session_dir: Path) -> None:
        self._session_dir = session_dir
        self._helper_addon_id: str | None = None
        self.webdriver = MagicMock()
        # Default behaviour: chrome-context install reports success with
        # the manifest-pinned id. Tests override per-call as needed.
        self.webdriver.execute_async_script.return_value = {
            "ok": True,
            "id": HELPER_EXTENSION_ID,
            "version": "0.1.0",
            "isActive": True,
        }


@pytest.fixture()
def driver_and_session(tmp_path: Path) -> tuple[_FakeDriver, Path]:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    driver = _FakeDriver(session_dir)
    # The Marionette-driven install_addon path reads the prepacked XPI
    # from <session_dir>/helper-extension.xpi. Pre-populate it for the
    # install_helper tests that don't run prepare_helper_install first.
    (session_dir / "helper-extension.xpi").write_bytes(b"placeholder")
    return driver, session_dir


def test_pack_helper_xpi_writes_valid_zip(tmp_path: Path) -> None:
    target = tmp_path / "helper.xpi"
    pack_helper_xpi(target, host="127.0.0.1", port=9999, token="t0k3n")

    assert target.is_file()
    assert zipfile.is_zipfile(target)
    with zipfile.ZipFile(target) as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names
        assert "background.js" in names
        assert "config.json" in names
        # Python package machinery must not leak into the XPI.
        assert not any(n.startswith("__pycache__/") for n in names)
        assert "__init__.py" not in names
        config = json.loads(zf.read("config.json").decode("utf-8"))
    assert config == {
        "bridge_host": "127.0.0.1",
        "bridge_port": 9999,
        "token": "t0k3n",
        "version": "0.1.0",
    }


def test_pack_helper_xpi_overwrites_stale(tmp_path: Path) -> None:
    """A stale ``config.json`` must not leak into a re-packed XPI."""

    target = tmp_path / "helper.xpi"
    pack_helper_xpi(target, host="127.0.0.1", port=8080, token="alpha")
    pack_helper_xpi(target, host="127.0.0.1", port=8081, token="beta")
    with zipfile.ZipFile(target) as zf:
        config = json.loads(zf.read("config.json").decode("utf-8"))
    assert config["bridge_port"] == 8081
    assert config["token"] == "beta"


def test_prepare_helper_install_writes_xpi_under_session(
    driver_and_session: tuple[_FakeDriver, Path]
) -> None:
    driver, session_dir = driver_and_session
    bridge = _FakeBridge(port=15000, token="secret-token")

    xpi_path = prepare_helper_install(driver, MagicMock(name="config"), bridge)

    assert xpi_path == session_dir / "helper-extension.xpi"
    assert xpi_path.is_file()
    with zipfile.ZipFile(xpi_path) as zf:
        config = json.loads(zf.read("config.json").decode("utf-8"))
    assert config["bridge_port"] == 15000
    assert config["token"] == "secret-token"


def test_install_helper_invokes_chrome_context_and_records_id(
    driver_and_session: tuple[_FakeDriver, Path]
) -> None:
    driver, session_dir = driver_and_session
    driver.webdriver.execute_async_script.return_value = {
        "ok": True,
        "id": "addon-xyz",
        "version": "0.1.0",
        "isActive": True,
    }
    bridge = _FakeBridge()
    install_helper(driver, MagicMock(name="config"), bridge)
    assert driver._helper_addon_id == "addon-xyz"
    driver.webdriver.set_context.assert_any_call("chrome")
    driver.webdriver.set_context.assert_any_call("content")
    driver.webdriver.execute_async_script.assert_called_once()
    args, _kwargs = driver.webdriver.execute_async_script.call_args
    # Second positional arg is the XPI path forwarded to AddonManager.
    expected_path = str(session_dir / "helper-extension.xpi")
    assert args[1] == expected_path


def test_install_helper_grants_private_browsing_permission(
    driver_and_session: tuple[_FakeDriver, Path]
) -> None:
    """Install path must grant private-browsing access before AddonManager runs.

    Tor Browser runs in permanent private browsing; without
    ``internal:privateBrowsingAllowed`` granted on the gecko id before
    ``installTemporaryAddon`` resolves, ext-backgroundPage.js short-
    circuits and the background page is never built. The chrome script
    must carry both an ``ExtensionPermissions.add`` call against the
    pinned gecko id and the addon id as its second argument.
    """

    driver, _ = driver_and_session
    bridge = _FakeBridge()
    install_helper(driver, MagicMock(name="config"), bridge)

    args, _kwargs = driver.webdriver.execute_async_script.call_args
    script_body = args[0]
    assert "ExtensionPermissions.add" in script_body
    assert "internal:privateBrowsingAllowed" in script_body
    # The addon id is the third positional argument (script, xpi_path, addon_id).
    assert args[2] == HELPER_EXTENSION_ID


def test_install_helper_token_mismatch_raises(
    driver_and_session: tuple[_FakeDriver, Path]
) -> None:
    driver, _ = driver_and_session
    bridge = _FakeBridge(connect_immediately=True, connect_but_reject=True)
    with pytest.raises(BrowserLaunchError):
        install_helper(driver, MagicMock(name="config"), bridge)
    assert bridge.close_called is True
    # Install + uninstall both go through execute_async_script in chrome
    # context. Two invocations: one to register, one to remove.
    assert driver.webdriver.execute_async_script.call_count >= 2


def test_install_helper_timeout_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Drop the install-time handshake deadline so the test does not sleep
    # for the full ten-second budget.
    monkeypatch.setattr(
        "torbrowser_driver._helper_extension_install._BRIDGE_HANDSHAKE_TIMEOUT",
        0.1,
    )
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        session_dir = Path(tmp)
        (session_dir / "helper-extension.xpi").write_bytes(b"x")
        driver = _FakeDriver(session_dir)
        bridge = _FakeBridge(connect_immediately=False)
        with pytest.raises(BrowserLaunchError):
            install_helper(driver, MagicMock(name="config"), bridge)
        assert bridge.close_called is True


def test_install_helper_install_failure_closes_bridge(
    driver_and_session: tuple[_FakeDriver, Path]
) -> None:
    driver, _ = driver_and_session
    driver.webdriver.execute_async_script.return_value = {
        "ok": False,
        "error": "installTemporaryAddon rejected XPI",
    }
    bridge = _FakeBridge()
    with pytest.raises(BrowserLaunchError):
        install_helper(driver, MagicMock(name="config"), bridge)
    assert bridge.close_called is True


def test_uninstall_helper_invokes_chrome_context_and_closes(
    driver_and_session: tuple[_FakeDriver, Path]
) -> None:
    driver, _ = driver_and_session
    bridge = _FakeBridge()
    install_helper(driver, MagicMock(name="config"), bridge)
    assert driver._helper_addon_id == HELPER_EXTENSION_ID

    uninstall_helper(driver, MagicMock(name="config"), bridge)
    # Last execute_async_script call is the uninstall, with the addon id
    # as the trailing positional argument.
    args, _kwargs = driver.webdriver.execute_async_script.call_args
    assert args[-1] == HELPER_EXTENSION_ID
    assert bridge.close_called is True
    assert driver._helper_addon_id is None


def test_uninstall_helper_swallows_close_errors(
    driver_and_session: tuple[_FakeDriver, Path]
) -> None:
    driver, _ = driver_and_session
    bridge = _FakeBridge()
    install_helper(driver, MagicMock(name="config"), bridge)
    driver.webdriver.execute_async_script.side_effect = RuntimeError("already gone")
    uninstall_helper(driver, MagicMock(name="config"), bridge)
    assert bridge.close_called is True


def test_helper_extension_source_is_complete() -> None:
    """Sanity: the package directory contains everything the packer ships."""

    assert (HELPER_EXTENSION_DIR / "manifest.json").is_file()
    assert (HELPER_EXTENSION_DIR / "background.js").is_file()
    # config.json is generated per-session, never shipped in the package.
    assert not (HELPER_EXTENSION_DIR / "config.json").exists()
