"""Install and uninstall the helper WebExtension for one driver session.

The extension source lives under :mod:`torbrowser_driver._helper_extension`.
Each session gets a freshly-built XPI under
``<session_dir>/helper-extension.xpi`` with a per-session ``config.json``
baked in (bridge host, port and shared-secret token), and is installed
by driving ``AddonManager.installTemporaryAddon`` from a chrome-context
script. Marionette's own ``INSTALL_ADDON`` WebDriver command returns the
manifest-declared id without actually registering the addon on Tor
Browser 15 / geckodriver 0.36 (the addon never reaches AddonManager), so
the driver bypasses it and calls the platform API directly. ``temporary``
installs bypass signature enforcement and are scoped to the browser
process lifetime.
"""

from __future__ import annotations

import contextlib
import json
import logging
import zipfile
from pathlib import Path
from typing import Any

from ._helper_extension import HELPER_EXTENSION_DIR, HELPER_EXTENSION_ID
from ._helper_extension_bridge import HelperBridge
from .config import DriverConfig
from .exceptions import BrowserLaunchError

log = logging.getLogger(__name__)


_BRIDGE_HANDSHAKE_TIMEOUT = 10.0
_HELPER_EXTENSION_VERSION = "0.1.0"

# Chrome-context async script. The trailing argument is the asyncResult
# callback Marionette injects; the leading argument is the XPI path. The
# script must return a JSON-serialisable value because Selenium round-
# trips it through the wire protocol.
_INSTALL_ADDON_JS = r"""
const cb = arguments[arguments.length - 1];
const xpiPath = arguments[0];
const addonId = arguments[1];
(async () => {
  try {
    const { AddonManager } = ChromeUtils.importESModule(
      "resource://gre/modules/AddonManager.sys.mjs"
    );
    const { FileUtils } = ChromeUtils.importESModule(
      "resource://gre/modules/FileUtils.sys.mjs"
    );
    const { ExtensionPermissions } = ChromeUtils.importESModule(
      "resource://gre/modules/ExtensionPermissions.sys.mjs"
    );
    // Tor Browser runs in permanent private browsing; without this
    // permission Extension._setupStartupPermissions does not grant
    // private-browsing access to temporarily-installed extensions, and
    // ext-backgroundPage.js's onManifestEntry short-circuits before the
    // background page is built. Grant the permission against the known
    // gecko id before installTemporaryAddon so the live Extension picks
    // it up on first startup.
    await ExtensionPermissions.add(addonId, {
      permissions: ["internal:privateBrowsingAllowed"],
      origins: [],
    });
    const file = new FileUtils.File(xpiPath);
    if (!file.exists()) {
      cb({ ok: false, error: "xpi not found at " + xpiPath });
      return;
    }
    const addon = await AddonManager.installTemporaryAddon(file);
    cb({ ok: true, id: addon.id, version: addon.version, isActive: addon.isActive });
  } catch (e) {
    cb({ ok: false, error: String(e), stack: e && e.stack ? String(e.stack) : null });
  }
})();
"""

_UNINSTALL_ADDON_JS = r"""
const cb = arguments[arguments.length - 1];
const addonId = arguments[0];
(async () => {
  try {
    const { AddonManager } = ChromeUtils.importESModule(
      "resource://gre/modules/AddonManager.sys.mjs"
    );
    const addon = await AddonManager.getAddonByID(addonId);
    if (!addon) {
      cb({ ok: true, removed: false });
      return;
    }
    await addon.uninstall();
    cb({ ok: true, removed: true });
  } catch (e) {
    cb({ ok: false, error: String(e) });
  }
})();
"""


def _session_dir(driver: Any) -> Path:
    session_dir = getattr(driver, "_session_dir", None)
    if session_dir is None:
        raise BrowserLaunchError(
            "helper-extension install requires a driver session directory"
        )
    return Path(session_dir)


def pack_helper_xpi(
    target: Path, *, host: str, port: int, token: str
) -> Path:
    """Build the session XPI at ``target`` with ``config.json`` baked in.

    The XPI is a deflate-zip containing the contents of
    :data:`HELPER_EXTENSION_DIR` plus a generated ``config.json`` carrying
    the per-session bridge host, port and shared-secret token. Returns
    ``target``.
    """

    target.parent.mkdir(parents=True, exist_ok=True)
    config_payload = json.dumps(
        {
            "bridge_host": host,
            "bridge_port": port,
            "token": token,
            "version": _HELPER_EXTENSION_VERSION,
        },
        separators=(",", ":"),
    )
    if target.exists():
        target.unlink()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in sorted(HELPER_EXTENSION_DIR.rglob("*")):
            if entry.is_dir():
                continue
            arcname = entry.relative_to(HELPER_EXTENSION_DIR).as_posix()
            if arcname == "config.json":
                continue
            if arcname.startswith("__pycache__/") or arcname == "__init__.py":
                continue
            zf.write(entry, arcname)
        zf.writestr("config.json", config_payload)
    return target


def prepare_helper_install(
    driver: Any, config: DriverConfig, bridge: HelperBridge
) -> Path:
    """Pack the session XPI under ``<session_dir>/helper-extension.xpi``.

    Called by :class:`TorBrowserDriver` before ``launch_browser`` so the
    bridge port and token are pinned in the XPI's ``config.json`` before
    Firefox boots. The bridge listener is started separately by the
    driver - both must be live before Marionette hands the XPI to the
    browser, otherwise the background page dials a dead socket.
    """

    session_dir = _session_dir(driver)
    xpi_path = session_dir / "helper-extension.xpi"
    pack_helper_xpi(
        xpi_path,
        host=bridge.host,
        port=bridge.port,
        token=bridge.token,
    )
    log.debug("packed helper-extension XPI at %s", xpi_path)
    return xpi_path


def _install_via_chrome(selenium_driver: Any, xpi_path: Path) -> str:
    """Drive ``AddonManager.installTemporaryAddon`` from chrome context.

    Returns the gecko id reported by AddonManager. Raises
    :class:`BrowserLaunchError` if the chrome eval cannot run or if the
    underlying install rejects the XPI.
    """

    try:
        selenium_driver.set_context("chrome")
    except Exception as exc:
        raise BrowserLaunchError(
            f"failed to switch Marionette to chrome context for install: {exc}"
        ) from exc
    try:
        selenium_driver.set_script_timeout(20)
        result = selenium_driver.execute_async_script(
            _INSTALL_ADDON_JS, str(xpi_path), HELPER_EXTENSION_ID
        )
    finally:
        with contextlib.suppress(Exception):
            selenium_driver.set_context("content")
    if not isinstance(result, dict) or not result.get("ok"):
        detail = (result or {}).get("error") if isinstance(result, dict) else result
        raise BrowserLaunchError(
            f"AddonManager.installTemporaryAddon rejected helper XPI: {detail}"
        )
    addon_id = result.get("id")
    if not isinstance(addon_id, str):
        raise BrowserLaunchError(
            f"AddonManager.installTemporaryAddon returned no addon id: {result!r}"
        )
    return addon_id


def _uninstall_via_chrome(selenium_driver: Any, addon_id: str) -> None:
    """Drive ``addon.uninstall()`` from chrome context. Best-effort."""

    with contextlib.suppress(Exception):
        selenium_driver.set_context("chrome")
        try:
            selenium_driver.set_script_timeout(10)
            selenium_driver.execute_async_script(_UNINSTALL_ADDON_JS, addon_id)
        finally:
            with contextlib.suppress(Exception):
                selenium_driver.set_context("content")


def install_helper(
    driver: Any, config: DriverConfig, bridge: HelperBridge
) -> None:
    """Install the session XPI via chrome-context AddonManager, then wait.

    Blocks for up to ten seconds waiting for the extension's background
    page to dial back into the bridge and complete the hello handshake.
    On failure - install error, handshake timeout, token rejection - the
    bridge listener is closed and :class:`BrowserLaunchError` is raised.

    Uses ``AddonManager.installTemporaryAddon`` instead of Marionette's
    ``INSTALL_ADDON`` command: the latter returns the manifest-declared
    id without actually registering the addon on Tor Browser 15 /
    geckodriver 0.36, leaving the helper invisible to AddonManager and
    the background page never started. Reaching AddonManager requires
    Firefox to have been launched with ``-remote-allow-system-access``,
    which :pyattr:`DriverConfig.allow_chrome_system_access` arranges for
    whenever ``helper-extension`` is enabled.
    """

    session_dir = _session_dir(driver)
    xpi_path = session_dir / "helper-extension.xpi"
    selenium_driver = getattr(driver, "webdriver", None)
    if selenium_driver is None:
        bridge.close()
        raise BrowserLaunchError(
            "helper-extension install requires a live Selenium WebDriver"
        )
    try:
        addon_id = _install_via_chrome(selenium_driver, xpi_path)
    except BrowserLaunchError:
        bridge.close()
        raise
    driver._helper_addon_id = addon_id

    signalled = bridge.connect_event.wait(_BRIDGE_HANDSHAKE_TIMEOUT)
    if not signalled:
        _uninstall_via_chrome(selenium_driver, addon_id)
        bridge.close()
        raise BrowserLaunchError(
            f"helper extension did not connect within "
            f"{_BRIDGE_HANDSHAKE_TIMEOUT:.0f}s"
        )
    if not bridge.connected:
        _uninstall_via_chrome(selenium_driver, addon_id)
        bridge.close()
        raise BrowserLaunchError(
            "helper extension connected but the hello handshake was rejected"
        )

    log.info(
        "helper extension bridge connected: id=%s bridge=%s:%d",
        addon_id,
        bridge.host,
        bridge.port,
    )


def uninstall_helper(
    driver: Any, config: DriverConfig, bridge: HelperBridge
) -> None:
    """Remove the temporary addon and close the bridge.

    Errors from either step are swallowed because this runs on the
    teardown path where Marionette may already be shut down.
    """

    addon_id = getattr(driver, "_helper_addon_id", None)
    selenium_driver = getattr(driver, "webdriver", None)
    if addon_id is not None and selenium_driver is not None:
        _uninstall_via_chrome(selenium_driver, addon_id)
    driver._helper_addon_id = None
    with contextlib.suppress(Exception):
        bridge.close()
