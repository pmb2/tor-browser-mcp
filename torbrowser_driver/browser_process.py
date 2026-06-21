"""Launch geckodriver and Tor Browser with the load-bearing recipe.

The recipe distinguishes Linux and Windows because the two platforms expose
different bundled-asset paths to the firefox binary. macOS is out of scope.

Linux:
  * ``LD_LIBRARY_PATH`` points at the bundled tor library directory so that
    firefox can resolve shared libraries shipped alongside it.
  * ``FONTCONFIG_PATH`` / ``FONTCONFIG_FILE`` point at the bundled fontconfig
    so Tor Browser uses its pinned font list instead of the system one.
  * ``HOME`` is overridden to ``<tbb_root>/Browser`` because TB resolves
    several bundled assets relative to ``$HOME``.
  * The geckodriver subprocess is launched with ``cwd=<tbb_root>/Browser``
    so firefox can locate its bundled fonts at the relative paths it expects.

Windows:
  * DLLs resolve from the executable directory; no ``LD_LIBRARY_PATH``
    analogue is needed.
  * DirectWrite handles fonts; no ``FONTCONFIG_*`` is needed.
  * ``HOME`` is not meaningful.
  * The subprocess CWD does not need to be the Browser directory.

In all cases the parent process CWD is left alone. ``cwd=`` is passed to the
geckodriver subprocess instead.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

from ._process_guardian import ProcessGuardian
from .exceptions import BrowserLaunchError

if TYPE_CHECKING:
    from .config import DriverConfig

log = logging.getLogger(__name__)


def _proxy_intercept_prefs_overlay(config: DriverConfig) -> dict[str, Any]:
    """Return the prefs overlay that replaces direct SOCKS-to-tor wiring.

    When ``proxy-intercept`` is enabled the browser must reach the
    local mitmproxy listener for both HTTP and HTTPS; mitmproxy then
    chains upstream through tor's SOCKS port via the in-tree
    HTTP-CONNECT-to-SOCKS5h adapter. The pref keys split into two
    groups:

    Keys that replace values from the default prefs:
      * ``network.proxy.type`` stays at ``1`` (manual proxy).
      * ``network.proxy.socks`` / ``socks_port`` / ``socks_remote_dns``
        are cleared so the browser does not bypass mitmproxy.
      * ``network.security.ports.banned.override`` widens to also
        whitelist ``intercept_port``.
      * ``network.dns.disabled`` is turned off. Stock TB disables DNS
        because every URL is routed through SOCKS5h to tor and the
        browser must never resolve locally; with an HTTP forward
        proxy, Firefox passes hostnames to mitmproxy via CONNECT and
        the URI-fixup path still needs DNS to function.
      * ``network.proxy.allow_hijacking_localhost`` is turned off so
        the loopback dial to mitmproxy itself is not recursively
        routed back through mitmproxy.
      * ``extensions.torbutton.use_nontor_proxy`` is enabled. TB's
        ``TorDomainIsolator`` registers as a protocol-proxy filter
        and rewrites every resolved proxy to a SOCKS entry (so each
        first-party domain gets its own circuit via SOCKS auth
        nonces). That filter short-circuits when this pref is set,
        which is the documented escape hatch for sessions that
        deliberately use a non-tor proxy. Without it, mitmproxy would
        be dialled as SOCKS5 and the HTTP CONNECT path never runs.

    Keys new to the overlay:
      * ``network.proxy.http`` / ``http_port`` / ``ssl`` / ``ssl_port``
        point at the local intercept listener on ``127.0.0.1``.
      * ``network.proxy.share_proxy_settings`` keeps the FTP / SOCKS
        sub-proxies consistent.
      * ``network.proxy.no_proxies_on`` is emptied so loopback dialup
        still flows through mitmproxy (the intercept proxy itself
        listens on loopback; bypassing it would mean missing flows).

    Only valid when ``"proxy-intercept"`` is in ``config.enabled_caps``.
    """

    return {
        "network.proxy.type": 1,
        "network.proxy.socks": "",
        "network.proxy.socks_port": 0,
        "network.proxy.socks_remote_dns": False,
        "network.security.ports.banned.override": (
            f"{config.socks_port},{config.control_port},{config.intercept_port}"
        ),
        "network.dns.disabled": False,
        "network.proxy.allow_hijacking_localhost": False,
        "extensions.torbutton.use_nontor_proxy": True,
        "network.proxy.http": "127.0.0.1",
        "network.proxy.http_port": config.intercept_port,
        "network.proxy.ssl": "127.0.0.1",
        "network.proxy.ssl_port": config.intercept_port,
        "network.proxy.share_proxy_settings": True,
        "network.proxy.no_proxies_on": "",
        # HTTPS-Only mode in Tor Browser / Firefox 128+ upgrades any
        # http:// navigation to https:// before the request reaches the
        # proxy substrate.  Mock-mode routes registered against http://
        # patterns would then see the upgraded https:// URL in
        # window.location rather than the original URL the caller
        # supplied, breaking the Playwright-style "fulfill on the
        # original URL" guarantee.  With the intercept proxy in place
        # TLS is already handled at the mitmproxy layer; disabling
        # HTTPS-Only here avoids the double-upgrade.
        "dom.security.https_only_mode": False,
        # The PBM variant applies specifically to private-browsing windows
        # (which TB opens by default); both prefs must be cleared together.
        "dom.security.https_only_mode_pbm": False,
    }


def _load_bearing_prefs(config: DriverConfig) -> dict[str, Any]:
    """Return the prefs that actually drive the TB-over-tor wiring.

    These are the prefs whose absence is known to break the launch path:
    the SOCKS proxy pointing at our bundled tor, the banned-ports override
    that lets Firefox connect to our non-standard SOCKS/control ports, the
    update kill switch, the load strategy, and the TB-specific prompt
    suppressors.
    """

    download_dir = str(config.path_policy.output_dir)
    never_ask_mime = ",".join(
        (
            "application/pdf",
            "application/octet-stream",
            "application/zip",
            "application/x-tar",
            "application/gzip",
            "application/json",
            "text/csv",
            "text/plain",
            "application/xml",
            "image/png",
            "image/jpeg",
        )
    )
    prefs: dict[str, Any] = {
        "network.proxy.type": 1,
        "network.proxy.socks": "127.0.0.1",
        "network.proxy.socks_port": config.socks_port,
        "network.proxy.socks_version": 5,
        "network.proxy.socks_remote_dns": True,
        "network.proxy.no_proxies_on": "",
        "network.security.ports.banned.override": (
            f"{config.socks_port},{config.control_port}"
        ),
        "app.update.enabled": False,
        "browser.shell.checkDefaultBrowser": False,
        "browser.startup.homepage_override.mstone": "ignore",
        "webdriver.load.strategy": "normal",
        "torbrowser.settings.quickstart.enabled": True,
        "intl.language_notification.shown": True,
        "browser.download.folderList": 2,
        "browser.download.dir": download_dir,
        "browser.download.useDownloadDir": True,
        "browser.download.manager.showWhenStarting": False,
        "browser.helperApps.neverAsk.saveToDisk": never_ask_mime,
        "pdfjs.disabled": True,
        # --- HARDENED AUTOMATION PROFILE ---
        # Suppress navigator.webdriver flag
        "dom.webdriver.enabled": False,
        "marionette.enabled": False,
        "useAutomationExtension": False,
        # Disable WebRTC (IP leak vector)
        "media.peerconnection.enabled": False,
        "media.peerconnection.ice.obfuscate_host_addresses": True,
        # Disable geolocation
        "geo.enabled": False,
        "geo.provider.use_corelocation": False,
        "geo.provider.use_gpsd": False,
        "geo.provider.use_geoclue": False,
        # Disable telemetry
        "toolkit.telemetry.enabled": False,
        "toolkit.telemetry.unified": False,
        "toolkit.telemetry.archive.enabled": False,
        "datareporting.healthreport.uploadEnabled": False,
        "datareporting.policy.dataSubmissionEnabled": False,
        # Disable notifications
        "dom.webnotifications.enabled": False,
        "dom.push.enabled": False,
        # Sanitize on shutdown
        "privacy.sanitize.sanitizeOnShutdown": True,
        "privacy.clearOnShutdown.cache": True,
        "privacy.clearOnShutdown.cookies": True,
        "privacy.clearOnShutdown.downloads": True,
        "privacy.clearOnShutdown.formdata": True,
        "privacy.clearOnShutdown.history": True,
        "privacy.clearOnShutdown.offlineApps": True,
        "privacy.clearOnShutdown.sessions": True,
        "privacy.clearOnShutdown.siteSettings": True,
        # Resist fingerprinting (overlay on top of Tor's RFP)
        "privacy.resistFingerprinting": True,
        "privacy.trackingprotection.fingerprinting.enabled": True,
        "privacy.trackingprotection.cryptomining.enabled": True,
        # Disable password manager
        "signon.rememberSignons": False,
        "signon.autofillForms": False,
        # Disable health reports
        "browser.selfsupport.url": "",
        "browser.crashReports.unsubmittedCheck.autoSubmit": False,
        "browser.crashReports.unsubmittedCheck.enabled": False,
        # Disable Pocket
        "extensions.pocket.enabled": False,
        # Disable form autofill
        "browser.formfill.enable": False,
        # Disable safe browsing checks (privacy)
        "browser.safebrowsing.enabled": False,
        "browser.safebrowsing.malware.enabled": False,
        "browser.safebrowsing.phishing.enabled": False,
        # Disable speculative connections
        "network.http.speculative-parallel-limit": 0,
        "network.dns.disablePrefetch": True,
        "network.prefetch-next": False,
        # Disable link prefetch
        "network.predictor.enabled": False,
        "network.predictor.enable-prefetch": False,
    }
    if config.include_legacy_tor_prefs:
        prefs.update(
            {
                "extensions.torlauncher.start_tor": False,
                "extensions.torlauncher.prompt_at_startup": False,
                "extensions.torlauncher.control_port": config.control_port,
                "extensions.torlauncher.socks_port": config.socks_port,
                "extensions.torbutton.launch_warning": False,
                "extensions.torbutton.local_tor_check": False,
                "extensions.torbutton.use_nontor_proxy": True,
            }
        )
    if "helper-extension" in config.enabled_caps:
        # TBB ships network.proxy.allow_hijacking_localhost=true (bug 31065)
        # so loopback destinations are also routed through the SOCKS proxy.
        # The helper extension's background page dials 127.0.0.1:<bridge_port>
        # over a plain WebSocket; with hijacking on, that connection would be
        # handed to tor's SOCKS, which refuses private-IP destinations and
        # the dial-back never reaches the driver. Disabling hijacking and
        # naming 127.0.0.1/localhost in no_proxies_on keeps the bridge
        # reachable while leaving every other request on the SOCKS path.
        prefs["network.proxy.allow_hijacking_localhost"] = False
        prefs["network.proxy.no_proxies_on"] = "127.0.0.1,localhost"
        # Profile-scope sideload: the session XPI is dropped under
        # <profile>/extensions/<id>.xpi and Firefox discovers it at
        # profile init. autoDisableScopes=0 keeps newly-discovered
        # extensions enabled instead of waiting for a UI confirmation;
        # enabledScopes=15 leaves every install scope (profile, user,
        # app, system) eligible to load; signatures.required=false is
        # defensive against future ESR builds tightening unsigned
        # sideload (current TB ESR honours this pref).
        prefs["extensions.autoDisableScopes"] = 0
        prefs["extensions.enabledScopes"] = 15
        prefs["xpinstall.signatures.required"] = False
        # Run the helper in the parent process. With out-of-process
        # extensions (the Firefox default), webRequest's
        # filterResponseData on top-level navigations and many
        # cross-process subresources does not deliver bytes through
        # ondata even though the filter object attaches and onstop
        # fires; co-locating the extension with the network stack
        # restores the byte stream.
        prefs["extensions.webextensions.remote"] = False
    if "proxy-intercept" in config.enabled_caps:
        prefs.update(_proxy_intercept_prefs_overlay(config))
    return prefs


def _build_profile(config: DriverConfig, session_dir: Path) -> FirefoxProfile:
    """Materialise the on-disk Firefox profile selenium will load."""

    if config.profile_mode == "ephemeral":
        target = session_dir / "profile"
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(config.default_profile_path, target)
        profile_dir = target
    else:
        assert config.profile_path is not None  # enforced by DriverConfig
        profile_dir = Path(config.profile_path)
        if not profile_dir.is_dir():
            raise BrowserLaunchError(
                f"persistent profile_path {profile_dir!s} does not exist"
            )

    profile = FirefoxProfile(str(profile_dir))
    prefs = _load_bearing_prefs(config)
    prefs.update(dict(config.extra_prefs))
    for key, value in prefs.items():
        profile.set_preference(key, value)
    profile.update_preferences()
    return profile


def _build_env(config: DriverConfig) -> dict[str, str]:
    """Return the environment to pass to the geckodriver subprocess."""

    env = os.environ.copy()
    browser_dir = str(config.browser_dir)
    tor_dir = str(config.tor_path.parent)

    if sys.platform == "linux":
        env["LD_LIBRARY_PATH"] = tor_dir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        fontconfig_dir = config.browser_dir / "TorBrowser" / "Data" / "fontconfig"
        fontconfig_file = fontconfig_dir / "fonts.conf"
        if fontconfig_dir.is_dir():
            env["FONTCONFIG_PATH"] = str(fontconfig_dir)
        if fontconfig_file.is_file():
            env["FONTCONFIG_FILE"] = str(fontconfig_file)
        # Preserve XAUTHORITY before overriding HOME so Firefox can still
        # authenticate against the X server.  When the caller did not set
        # XAUTHORITY explicitly, derive it from the *real* home directory
        # (the value of HOME before we replace it) so the override does not
        # lose the X cookie path.
        if "XAUTHORITY" not in env:
            real_xauth = Path(env["HOME"]) / ".Xauthority"
            if real_xauth.is_file():
                env["XAUTHORITY"] = str(real_xauth)
        env["HOME"] = browser_dir

    # Prepending Browser/ and the tor subdir to PATH is harmless on both
    # platforms and helps firefox find sibling binaries on Windows where
    # DLL resolution walks PATH.
    env["PATH"] = browser_dir + os.pathsep + tor_dir + os.pathsep + env.get("PATH", "")
    return env


def _resolve_geckodriver(config: DriverConfig) -> str:
    """Resolve the geckodriver binary path for this session.

    Resolution order:

    1. ``config.geckodriver_path`` if the caller supplied one. This
       short-circuits every other step and never touches the network.
    2. ``<tbb_root>/Browser/geckodriver`` if it exists and is executable.
       Older Tor Browser releases shipped geckodriver inside the tarball;
       users who placed one there manually are also covered.
    3. A ``geckodriver`` binary on ``PATH``.
    4. The on-first-run resolver in :mod:`._geckodriver_resolver`, which
       downloads the version matching the bundle's Firefox ESR into
       ``~/.cache/tor-browser-mcp/geckodriver/<version>/``. Subsequent
       sessions reuse the cached binary.
    """

    if config.geckodriver_path is not None:
        return str(config.geckodriver_path)
    bundled = config.tbb_root / "Browser" / "geckodriver"
    if bundled.is_file() and os.access(bundled, os.X_OK):
        log.info("geckodriver: using bundled binary at %s", bundled)
        return str(bundled)
    located = shutil.which("geckodriver")
    if located:
        return located
    try:
        from ._geckodriver_resolver import (
            GeckodriverResolveError,
            resolve_geckodriver,
        )

        return str(resolve_geckodriver(tbb_root=config.tbb_root))
    except GeckodriverResolveError as exc:
        raise BrowserLaunchError(
            f"geckodriver_path is None, no 'geckodriver' binary was found on PATH, "
            f"and the on-first-run resolver failed: {exc}"
        ) from exc


def launch_browser(
    config: DriverConfig,
    *,
    marionette_port: int | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
) -> tuple[webdriver.Firefox, Path]:
    """Launch Tor Browser via geckodriver and return ``(driver, session_dir)``.

    ``session_dir`` holds any temporary state owned by this launch (an
    ephemeral profile copy, the geckodriver log). When the caller does not
    pass one, a temporary directory is created and returned for cleanup.

    ``marionette_port`` is forwarded to geckodriver as ``--marionette-port``.
    When ``None``, geckodriver picks a free port itself.
    """

    owns_session_dir = session_dir is None
    if owns_session_dir:
        session_dir = Path(tempfile.mkdtemp(prefix="torbrowser-driver-"))
    assert session_dir is not None

    options = Options()
    options.binary_location = str(config.firefox_path)
    if config.headless:
        options.add_argument("-headless")
    if config.allow_chrome_system_access:
        options.add_argument("-remote-allow-system-access")
    options.profile = _build_profile(config, session_dir)

    env = _build_env(config)

    service_kwargs: dict[str, Any] = {
        "executable_path": _resolve_geckodriver(config),
        "port": 0,
        "env": env,
    }
    if log_path is None:
        log_path = session_dir / "geckodriver.log"
    service_kwargs["log_output"] = str(log_path)
    if marionette_port is not None:
        service_kwargs["service_args"] = ["--marionette-port", str(marionette_port)]

    service = Service(**service_kwargs)

    # Pass cwd to the geckodriver subprocess on Linux so firefox finds its
    # bundled fonts. Selenium's Service does not surface cwd; reach through
    # to the popen_kw bag where supported.
    if sys.platform == "linux":
        popen_kw = getattr(service, "popen_kw", None)
        if isinstance(popen_kw, dict):
            popen_kw["cwd"] = str(config.browser_dir)
        else:
            service.popen_kw = {"cwd": str(config.browser_dir)}

    log.info(
        "starting Tor Browser via geckodriver: binary=%s profile_mode=%s headless=%s",
        config.firefox_path,
        config.profile_mode,
        config.headless,
    )
    try:
        driver = webdriver.Firefox(service=service, options=options)
    except WebDriverException as exc:
        raise BrowserLaunchError(
            f"geckodriver/Tor Browser failed to start: {exc}"
        ) from exc

    gecko_proc = getattr(service, "process", None)
    gecko_pid = getattr(gecko_proc, "pid", None)
    if isinstance(gecko_pid, int):
        ProcessGuardian.instance().adopt(gecko_pid)

    return driver, session_dir
