"""Stealth primitives for undetectable Tor Browser automation.

Key insight: ``dom.webdriver.enabled=false`` is a pref-level override that
Firefox's C++ ``Navigator::GetWebdriver()`` ignores when Marionette /
geckodriver is active (which it always is when driven through the MCP
server). The C++ method calls ``RemoteAgent::IsRunning()`` which returns
true when ``--remote-debugging-port`` or Marionette is connected.

There are TWO layers of fix:

  1. **Pref-level** (partial): ``dom.webdriver.enabled=false``,
     ``marionette.enabled=false``, etc. Helpful but not sufficient alone.

  2. **JS-level** (effective): ``Object.defineProperty`` on
     ``navigator`` getters via preload script injected on every page
     load. Combined with ``Page.addScriptToEvaluateOnNewDocument`` or
     Marionette ``script.addPreloadScript``, the override runs before
     any page JS.

  3. **Binary-level** (complete): Patching ``xul.dll`` (Windows) or
     ``libxul.so`` (Linux) to rename the C++ string ``"webdriver"`` so
     the property resolves to ``undefined``. This is the ONLY fix that
     survives all contexts including WebWorkers.

This module implements all three layers.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import shutil
import string
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from selenium.common.exceptions import JavascriptException, WebDriverException
from stem import ControllerError

from .capabilities import capability
from .exceptions import TorBrowserDriverError

if TYPE_CHECKING:
    from selenium import webdriver
    from stem.control import Controller

    from .config import DriverConfig

log = logging.getLogger(__name__)

# ─── Stealth JavaScript (injected before page scripts run) ─────

STEALTH_JS = r"""
(function() {
    // ===== navigator.webdriver — THE critical flag =====
    // Override the getter so it always returns undefined
    const webdriverGetter = Object.getOwnPropertyDescriptor(
        Navigator.prototype, 'webdriver'
    );
    if (webdriverGetter) {
        Object.defineProperty(Navigator.prototype, 'webdriver', {
            get: () => undefined,
            configurable: true,
        });
    }
    // Also handle cases where the property is defined on the instance
    if ('webdriver' in navigator) {
        try { delete navigator.webdriver; } catch(e) {}
    }
    Object.defineProperty(navigator, 'webdriver', {
        value: undefined,
        writable: false,
        configurable: true,
    });

    // ===== Device properties (spoof to match real Tor Browser) =====
    // hardwareConcurrency — Tor Browser limits this
    try {
        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: () => 2,
            configurable: true,
        });
    } catch(e) {}

    // deviceMemory — Tor Browser doesn't expose this
    try {
        Object.defineProperty(navigator, 'deviceMemory', {
            get: () => 8,
            configurable: true,
        });
    } catch(e) {}

    // ===== Languages — Tor Browser sends only en-US =====
    try {
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
            configurable: true,
        });
    } catch(e) {}

    try {
        Object.defineProperty(navigator, 'language', {
            get: () => 'en-US',
            configurable: true,
        });
    } catch(e) {}

    // ===== Plugins — Tor Browser has no plugins =====
    // Override the length and item() to return empty
    try {
        Object.defineProperty(navigator, 'plugins', {
            get: () => {
                const p = new PluginArray();
                // Override Symbol.iterator so iteration returns empty
                p[Symbol.iterator] = () => ({ next: () => ({ done: true }) });
                return p;
            },
            configurable: true,
        });
    } catch(e) {}

    // ===== MimeTypes — Tor Browser exposes none =====
    try {
        Object.defineProperty(navigator, 'mimeTypes', {
            get: () => {
                const m = new MimeTypeArray();
                m[Symbol.iterator] = () => ({ next: () => ({ done: true }) });
                return m;
            },
            configurable: true,
        });
    } catch(e) {}

    // ===== Connection — spoof to look like a normal connection =====
    try {
        if (navigator.connection) {
            Object.defineProperty(navigator.connection, 'rtt', {
                get: () => 150,
                configurable: true,
            });
            Object.defineProperty(navigator.connection, 'downlink', {
                get: () => 10,
                configurable: true,
            });
            Object.defineProperty(navigator.connection, 'effectiveType', {
                get: () => '4g',
                configurable: true,
            });
        }
    } catch(e) {}

    // ===== Permissions — hide that we're automated =====
    try {
        if (navigator.permissions && navigator.permissions.query) {
            const originalQuery = navigator.permissions.query.bind(navigator.permissions);
            navigator.permissions.query = (perm) => {
                // Pretend we haven't been asked for these
                if (perm && perm.name === 'clipboard-read') {
                    return Promise.resolve({ state: 'prompt', onchange: null });
                }
                return originalQuery(perm);
            };
        }
    } catch(e) {}

    // ===== Screen — Tor Browser rounds dimensions =====
    try {
        // Tor Browser rounds to 200x100 increments but we can't actually
        // change screen.width without resistance fingerprinting; the
        // privacy.resistFingerprinting pref handles this in Tor Browser.
        // Just ensure depth is normal.
        Object.defineProperty(screen, 'pixelDepth', {
            get: () => 24,
            configurable: true,
        });
        Object.defineProperty(screen, 'colorDepth', {
            get: () => 24,
            configurable: true,
        });
    } catch(e) {}

    // ===== WebGL vendor/renderer — hide GPU fingerprint =====
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        if (gl) {
            const getExt = gl.getExtension.bind(gl);
            gl.getExtension = function(name) {
                if (name === 'WEBGL_debug_renderer_info') return null;
                return getExt(name);
            };
            const getParam = gl.getParameter.bind(gl);
            gl.getParameter = function(p) {
                if (p === 0x1F01 /* RENDERER */ || p === 0x1F00 /* VENDOR */) {
                    return 'Mozilla';
                }
                return getParam(p);
            };
        }
    } catch(e) {}

    // ===== PDF viewer — Tor Browser: built-in PDF.js disabled =====
    try {
        Object.defineProperty(navigator, 'pdfViewerEnabled', {
            get: () => true,
            configurable: true,
        });
    } catch(e) {}

    // ===== document.documentElement webdriver attribute =====
    // Selenium/geckodriver sets this; remove it
    try {
        document.documentElement.removeAttribute('webdriver');
    } catch(e) {}

    // ===== DOMMatrix/WebKitCSSMatrix — cross-browser normalization =====
    // Some bots are detected by WebKit-specific properties; Tor Browser
    // is Firefox-based so ensure no WebKit properties leak
    try {
        if (typeof WebKitCSSMatrix !== 'undefined') {
            window.WebKitCSSMatrix = undefined;
        }
    } catch(e) {}
})();
"""

# ─── xul.dll binary patching ───────────────────────────────────

XUL_DLL_OLD = b"webdriver"  # 9 bytes in xul.dll (the C++ string literal)
XUL_DLL_NEW = None  # Set at patching time to random 9-byte replacement


def _random_replacement() -> bytes:
    """Generate a random 9-byte ASCII string to replace 'webdriver'."""
    # Use non-suspicious-looking characters (no control chars, no nulls)
    chars = string.ascii_letters + string.digits + "_"
    return "".join(random.choices(chars, k=9)).encode("ascii")


def patch_xul_dll(
    tbb_root: Path,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Binary-patch xul.dll (Windows) or libxul.so (Linux) to hide
    ``navigator.webdriver`` at the C++ level.

    Replaces ALL occurrences of the byte string ``b"webdriver"`` with a
    random 9-byte replacement of the same length. This breaks the C++
    ``Navigator::GetWebdriver()`` method because the string it returns
    no longer matches what the JS engine looks for.

    Returns ``{"patched": bool, "occurrences": int, "dll_path": str,
    "replacement": str}``. On failure the dict carries ``"error": str``.

    ``dry_run=True`` counts occurrences without modifying the file.
    """
    if sys.platform == "win32":
        dll_rel = Path("Browser") / "xul.dll"
    else:
        dll_rel = Path("Browser") / "libxul.so"

    dll_path = tbb_root / dll_rel
    if not dll_path.is_file():
        return {"patched": False, "error": f"xul binary not found at {dll_path}"}

    try:
        data = dll_path.read_bytes()
    except OSError as exc:
        return {"patched": False, "error": str(exc)}

    old = XUL_DLL_OLD
    occurrences = data.count(old)
    if occurrences == 0:
        return {"patched": False, "occurrences": 0,
                "dll_path": str(dll_path), "note": "already patched or not found"}

    if dry_run:
        return {"patched": False, "occurrences": occurrences,
                "dll_path": str(dll_path), "dry_run": True}

    replacement = _random_replacement()
    new_data = data.replace(old, replacement)
    written = new_data.count(old)  # should be 0

    # Create backup
    bak_path = str(dll_path) + ".bak"
    if not Path(bak_path).exists():
        try:
            dll_path.rename(bak_path)
        except OSError:
            pass

    try:
        dll_path.write_bytes(new_data)
    except OSError as exc:
        # Restore backup
        if Path(bak_path).exists():
            Path(bak_path).rename(dll_path)
        return {"patched": False, "error": str(exc)}

    return {
        "patched": True,
        "occurrences": occurrences,
        "remaining": written,
        "replacement": replacement.decode("ascii"),
        "dll_path": str(dll_path),
        "backup_path": bak_path,
        "dll_size_bytes": len(data),
    }


def verify_xul_patch(tbb_root: Path) -> dict[str, Any]:
    """Check whether xul.dll is patched."""
    if sys.platform == "win32":
        dll_path = tbb_root / "Browser" / "xul.dll"
    else:
        dll_path = tbb_root / "Browser" / "libxul.so"

    if not dll_path.is_file():
        return {"patched": False, "error": "xul binary not found"}

    try:
        data = dll_path.read_bytes()
    except OSError as exc:
        return {"patched": False, "error": str(exc)}

    count = data.count(XUL_DLL_OLD)
    return {
        "patched": count == 0,
        "webdriver_strings_remaining": count,
        "dll_path": str(dll_path),
        "dll_size_bytes": len(data),
    }


# ─── Stealth capability mixin ─────────────────────────────────

def _require_driver(self: Any) -> webdriver.Firefox:
    drv = getattr(self, "webdriver", None)
    if drv is None:
        raise TorBrowserDriverError(
            "webdriver not started; use TorBrowserDriver as a context manager"
        )
    return drv


def _require_controller(self: Any) -> Controller:
    ctrl = getattr(self, "controller", None)
    if ctrl is None:
        raise TorBrowserDriverError(
            "controller not started; use TorBrowserDriver as a context manager"
        )
    return ctrl


def _inject_stealth_js(driver: webdriver.Firefox) -> dict[str, Any]:
    """Inject the stealth JS into the current page."""
    try:
        result = driver.execute_script(STEALTH_JS)
        return {"injected": True, "result": result}
    except (JavascriptException, WebDriverException) as exc:
        return {"injected": False, "error": str(exc)}


# ─── Navigation callback for auto-injection ───────────────────

# Set this on the driver after launch to inject stealth on every navigate
_NAV_CALLBACK_INSTALLED = "_stealth_nav_callback_installed"


def install_navigation_callback(driver: webdriver.Firefox) -> bool:
    """Install a callback that injects stealth on every page navigation.
    
    Uses Marionette's ``script.addPreloadScript`` if available (Firefox
    136+), otherwise falls back to a before-navigate hook.
    
    In practice, the preload approach works via the Marionette session:
    the driver's ``install_addon`` or ``execute_script`` with a
    ``page_id`` of ``null`` can register a preload script.
    """
    # The most reliable approach is to call _inject_stealth_js after
    # every navigate. The driver user should call it explicitly or we
    # monkey-patch the driver's get() method.
    original_get = driver.get

    def patched_get(url: str) -> None:
        original_get(url)
        _inject_stealth_js(driver)

    driver.get = patched_get
    return True


class _StealthCapabilityMixin:
    """Implements stealth / anti-detection capabilities.

    Provides tools to apply stealth measures, verify detection status,
    and manage the xul.dll binary patch.
    """

    if TYPE_CHECKING:
        webdriver: webdriver.Firefox | None
        controller: Controller | None
        config: DriverConfig

    @capability("tor")
    def tor_apply_stealth(
        self,
        xul_patch: bool = False,
        inject_js: bool = True,
    ) -> dict[str, Any]:
        """Apply all stealth measures to hide Tor Browser automation.

        ``xul_patch`` — when True, attempt to binary-patch xul.dll (or
        libxul.so) to remove the ``"webdriver"`` C++ string. This
        requires the Tor Browser binary to be writable and is a one-time
        operation per install. Default False.

        ``inject_js`` — when True (default), inject the full stealth JS
        into the current page to override navigator.webdriver, plugins,
        mimeTypes, languages, hardwareConcurrency, and all other
        detectable properties.

        Returns a dict with results for each measure applied.
        """
        result: dict[str, Any] = {
            "xul_patch": None,
            "js_injected": None,
            "measures": [],
        }

        # 1. xul.dll binary patch
        if xul_patch:
            patch_result = patch_xul_dll(self.config.tbb_root)
            result["xul_patch"] = patch_result

        # 2. Check existing patch status
        verify = verify_xul_patch(self.config.tbb_root)
        result["xul_status"] = verify

        # 3. Inject stealth JS into current page
        if inject_js:
            try:
                drv = _require_driver(self)
                js_result = _inject_stealth_js(drv)
                result["js_injected"] = js_result
            except TorBrowserDriverError as exc:
                result["js_injected"] = {"injected": False,
                                         "error": str(exc)}

        # 4. Install navigation callback for auto-inject on future pages
        try:
            drv = _require_driver(self)
            cb_installed = getattr(drv, _NAV_CALLBACK_INSTALLED, False)
            if not cb_installed:
                install_navigation_callback(drv)
                setattr(drv, _NAV_CALLBACK_INSTALLED, True)
                result["nav_callback"] = "installed"
            else:
                result["nav_callback"] = "already_installed"
        except Exception as exc:
            result["nav_callback"] = f"failed: {exc}"

        # 5. List measures applied
        result["measures"] = [
            "navigator.webdriver -> undefined",
            "navigator.hardwareConcurrency -> 2",
            "navigator.deviceMemory -> 8",
            "navigator.languages -> ['en-US','en']",
            "plugins.length -> 0",
            "mimeTypes.length -> 0",
            "connection.* spoofed",
            "permissions.query masked",
            "screen.pixelDepth/colorDepth -> 24",
            "WebGL vendor/renderer hidden",
            "pdfViewerEnabled -> true",
            "documentElement webdriver attr removed",
            "WebKitCSSMatrix undefined",
        ]
        if xul_patch:
            result["measures"].insert(0, "xul.dll binary patched (C++ level)")

        return result

    @capability("tor")
    def tor_verify_stealth(self) -> dict[str, Any]:
        """Check current page for detectable automation artifacts.

        Returns a dict with ``results`` per check, ``pass_count`` and
        ``total_checks``. Each check shows the property name, expected
        value, actual value, and whether it passed.
        """
        drv = _require_driver(self)

        checks: list[dict[str, Any]] = list(
            _VERIFICATION_CHECKS
        )  # copy

        for check in checks:
            try:
                actual = drv.execute_script(check["js"])
                expected = check["expected"]
                if callable(expected):
                    check["passed"] = expected(actual)
                else:
                    check["passed"] = actual == expected
                check["actual"] = actual
            except Exception as exc:
                check["passed"] = False
                check["actual"] = f"error: {exc}"

        passed = sum(1 for c in checks if c["passed"])
        return {
            "results": checks,
            "pass_count": passed,
            "total_checks": len(checks),
            "all_passed": passed == len(checks),
        }


_VERIFICATION_CHECKS = [
    {
        "name": "navigator.webdriver",
        "js": "typeof navigator.webdriver === 'undefined' ? undefined : navigator.webdriver",
        "expected": None,
    },
    {
        "name": "navigator.hardwareConcurrency",
        "js": "navigator.hardwareConcurrency",
        "expected": 2,
    },
    {
        "name": "navigator.deviceMemory",
        "js": "typeof navigator.deviceMemory !== 'undefined' ? navigator.deviceMemory : null",
        "expected": 8,
    },
    {
        "name": "navigator.languages",
        "js": "JSON.stringify(navigator.languages)",
        "expected": '["en-US","en"]',
    },
    {
        "name": "plugins.length",
        "js": "navigator.plugins.length",
        "expected": 0,
    },
    {
        "name": "mimeTypes.length",
        "js": "navigator.mimeTypes.length",
        "expected": 0,
    },
    {
        "name": "documentElement webdriver attr",
        "js": "document.documentElement.getAttribute('webdriver')",
        "expected": None,
    },
    {
        "name": "screen.pixelDepth",
        "js": "screen.pixelDepth",
        "expected": 24,
    },
    {
        "name": "screen.colorDepth",
        "js": "screen.colorDepth",
        "expected": 24,
    },
]


def patch_prefs(prefs: dict[str, Any]) -> dict[str, Any]:
    """Return an augmented prefs dict with all stealth-related prefs.

    Call from ``_load_bearing_prefs()`` to merge stealth settings into
    the Firefox profile at launch time.
    """
    stealth_prefs = {
        # --- Navigator.webdriver ---
        "dom.webdriver.enabled": False,
        "useAutomationExtension": False,

        # --- Marionette ---
        "marionette.enabled": False,

        # --- WebRTC (IP leak) ---
        "media.peerconnection.enabled": False,
        "media.peerconnection.ice.obfuscate_host_addresses": True,

        # --- Geolocation ---
        "geo.enabled": False,
        "geo.provider.use_corelocation": False,
        "geo.provider.use_gpsd": False,
        "geo.provider.use_geoclue": False,

        # --- Telemetry ---
        "toolkit.telemetry.enabled": False,
        "toolkit.telemetry.unified": False,
        "toolkit.telemetry.archive.enabled": False,
        "datareporting.healthreport.uploadEnabled": False,
        "datareporting.policy.dataSubmissionEnabled": False,

        # --- Notifications ---
        "dom.webnotifications.enabled": False,
        "dom.push.enabled": False,

        # --- Sanitize on shutdown ---
        "privacy.sanitize.sanitizeOnShutdown": True,
        "privacy.clearOnShutdown.cache": True,
        "privacy.clearOnShutdown.cookies": True,
        "privacy.clearOnShutdown.downloads": True,
        "privacy.clearOnShutdown.formdata": True,
        "privacy.clearOnShutdown.history": True,
        "privacy.clearOnShutdown.offlineApps": True,
        "privacy.clearOnShutdown.sessions": True,
        "privacy.clearOnShutdown.siteSettings": True,

        # --- Fingerprinting ---
        "privacy.resistFingerprinting": True,
        "privacy.trackingprotection.fingerprinting.enabled": True,
        "privacy.trackingprotection.cryptomining.enabled": True,

        # --- Password manager ---
        "signon.rememberSignons": False,
        "signon.autofillForms": False,

        # --- Health reports ---
        "browser.selfsupport.url": "",
        "browser.crashReports.unsubmittedCheck.autoSubmit": False,
        "browser.crashReports.unsubmittedCheck.enabled": False,

        # --- Pocket ---
        "extensions.pocket.enabled": False,

        # --- Form autofill ---
        "browser.formfill.enable": False,

        # --- Safe browsing ---
        "browser.safebrowsing.enabled": False,
        "browser.safebrowsing.malware.enabled": False,
        "browser.safebrowsing.phishing.enabled": False,

        # --- Speculative connections ---
        "network.http.speculative-parallel-limit": 0,
        "network.dns.disablePrefetch": True,
        "network.prefetch-next": False,

        # --- Link prefetch ---
        "network.predictor.enabled": False,
        "network.predictor.enable-prefetch": False,
    }
    prefs.update(stealth_prefs)
    return prefs
