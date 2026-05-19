"""Diagnostics primitives implementing the ``diagnostics`` capability.

Surfaces best-effort browser-log capture, a JSON snapshot of the active
:class:`DriverConfig`, and a read-only fingerprint probe. None of these
methods modify browser state.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .capabilities import capability

if TYPE_CHECKING:
    from selenium import webdriver

    from .config import DriverConfig


_DEFAULT_CONSOLE_LIMIT = 100

_FINGERPRINT_JS = r"""
var screen = window.screen || {};
var nav = window.navigator || {};
var plugins = [];
try {
  for (var i = 0; i < (nav.plugins || []).length; i++) {
    plugins.push(nav.plugins[i].name);
  }
} catch (e) {
  plugins = [];
}
var tz = null;
try {
  tz = Intl.DateTimeFormat().resolvedOptions().timeZone || null;
} catch (e) {
  tz = null;
}
return {
  navigator_webdriver: 'webdriver' in nav ? !!nav.webdriver : null,
  user_agent: nav.userAgent || null,
  platform: nav.platform || null,
  language: nav.language || null,
  languages: nav.languages ? Array.from(nav.languages) : [],
  timezone: tz,
  screen: {
    width: screen.width || null,
    height: screen.height || null,
    color_depth: screen.colorDepth || null,
    device_pixel_ratio: window.devicePixelRatio || null,
  },
  window_inner: {
    width: window.innerWidth || null,
    height: window.innerHeight || null,
  },
  do_not_track: nav.doNotTrack || null,
  hardware_concurrency: nav.hardwareConcurrency || null,
  plugins: plugins,
};
"""


class _DiagnosticsCapabilityMixin:
    """Implements the ``diagnostics`` capability surface on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: "webdriver.Firefox | None"
        config: "DriverConfig"

        def _require_driver(self) -> "webdriver.Firefox": ...

    @capability("diagnostics")
    def browser_console_messages(
        self,
        level: str | None = None,
        include_all: bool = False,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Return browser-log messages when geckodriver exposes them.

        Current Firefox/geckodriver releases generally do not expose the
        ``browser`` log type. When :meth:`webdriver.get_log` raises, the
        method returns a stub ``{"messages": [], "supported": False, ...}``
        so callers can still rely on a uniform shape. When the log is
        available, ``level`` filters to one of ``"INFO"``, ``"WARNING"``,
        ``"SEVERE"``. ``include_all=False`` truncates to the most recent
        100 entries; ``include_all=True`` returns every captured entry.
        ``filename`` writes the JSON to disk.
        """

        drv = self._require_driver()

        try:
            raw = drv.get_log("browser")
            supported = True
        except Exception:
            payload = {
                "messages": [],
                "supported": False,
                "note": (
                    "Firefox/geckodriver did not expose browser log; "
                    "helper-extension capability is required for reliable capture"
                ),
            }
            if filename is not None:
                path = self.config.path_policy.resolve_output(filename)
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                path.write_bytes(data)
                return {"path": str(path), "bytes": len(data), **payload}
            return payload

        messages = list(raw or [])
        if level is not None:
            wanted = level.upper()
            messages = [
                m for m in messages if str(m.get("level", "")).upper() == wanted
            ]
        if not include_all and len(messages) > _DEFAULT_CONSOLE_LIMIT:
            messages = messages[-_DEFAULT_CONSOLE_LIMIT:]

        payload = {"messages": messages, "supported": supported}
        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data), **payload}
        return payload

    @capability("diagnostics")
    def browser_get_config(self) -> dict[str, Any]:
        """Return a JSON-safe snapshot of the active DriverConfig.

        Paths are stringified, ``enabled_caps`` is rendered as a sorted
        list, and the PathPolicy's ``output_dir`` and ``allowed_roots``
        are surfaced as strings so the result can flow straight back
        through an MCP tool boundary.
        """

        config = self.config
        policy = config.path_policy
        return {
            "tbb_root": str(config.tbb_root),
            "geckodriver_path": (
                str(config.geckodriver_path)
                if config.geckodriver_path is not None
                else None
            ),
            "profile_mode": config.profile_mode,
            "profile_path": (
                str(config.profile_path) if config.profile_path is not None else None
            ),
            "headless": bool(config.headless),
            "socks_port": int(config.socks_port),
            "control_port": int(config.control_port),
            "tor_data_dir": (
                str(config.tor_data_dir) if config.tor_data_dir is not None else None
            ),
            "enabled_caps": sorted(config.enabled_caps),
            "include_legacy_tor_prefs": bool(config.include_legacy_tor_prefs),
            "output_dir": str(policy.output_dir),
            "allowed_roots": [str(p) for p in policy.allowed_roots],
        }

    @capability("diagnostics")
    def browser_fingerprint_probe(self) -> dict[str, Any]:
        """Return a read-only snapshot of common fingerprint signals.

        This is a diagnostic only: the method does not attempt to suppress,
        randomise, or otherwise mask any signal. Returned fields cover the
        ``navigator`` flags Tor Browser is known to pin (UA, platform,
        languages, timezone, screen dimensions, hardware concurrency,
        plugin names) so callers can verify the live profile matches
        expectations.
        """

        drv = self._require_driver()
        result = drv.execute_script(_FINGERPRINT_JS) or {}
        return dict(result)
