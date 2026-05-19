"""Driver configuration.

:class:`DriverConfig` is the single source of truth for how a Tor Browser
session is launched: where Tor Browser lives, which geckodriver binary to
use, profile policy, headless flag, the SOCKS/control port pair for the
bundled tor we spawn, pref overrides, enabled capability groups, and the
filesystem :class:`~torbrowser_driver.path_policy.PathPolicy`.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Mapping

from .exceptions import DriverConfigError
from .path_policy import PathPolicy


ProfileMode = Literal["ephemeral", "persistent"]


def _firefox_relative() -> Path:
    """Path to the Tor Browser firefox executable, relative to ``tbb_root``."""

    if platform.system() == "Windows":
        return Path("Browser") / "firefox.exe"
    return Path("Browser") / "firefox"


def _tor_relative() -> Path:
    """Path to the bundled tor binary, relative to ``tbb_root``."""

    if platform.system() == "Windows":
        return Path("Browser") / "TorBrowser" / "Tor" / "tor.exe"
    return Path("Browser") / "TorBrowser" / "Tor" / "tor"


@dataclass(frozen=True)
class DriverConfig:
    """All inputs needed to launch a Tor Browser session.

    Attributes:
        tbb_root: Root of an extracted Tor Browser bundle. Must contain
            ``Browser/firefox(.exe)``.
        geckodriver_path: Path to a geckodriver binary compatible with the
            Firefox ESR version Tor Browser ships. ``None`` means look it up
            on ``PATH``.
        profile_mode: ``"ephemeral"`` copies the bundled
            ``profile.default`` into a session directory; ``"persistent"``
            reuses ``profile_path`` directly.
        profile_path: Persistent profile directory. Required when
            ``profile_mode == "persistent"``.
        headless: Pass ``-headless`` to Firefox. Headed is the recommended
            mode because it matches the fingerprint of a real Tor Browser
            user.
        socks_port: SOCKS port for the bundled tor we spawn. Defaults to a
            non-standard port (9250) to avoid collision with a system tor.
        control_port: Tor control port for the bundled tor we spawn.
        tor_data_dir: ``DataDirectory`` for the bundled tor. ``None`` means
            create a session-scoped temporary directory.
        extra_prefs: Additional Firefox prefs merged on top of the
            load-bearing defaults. Caller-supplied prefs win on key collision.
        include_legacy_tor_prefs: When ``True``, the driver also sets the
            ``extensions.torbutton.*`` / ``extensions.torlauncher.*`` family.
            Current Tor Browser releases integrated torbutton into the
            browser chrome and these prefs are believed to be no-ops there;
            kept available for older builds and Linux verification.
        enabled_caps: Capability groups the higher MCP layer will surface.
            Not consumed by the driver itself; tracked here so the same
            config object can flow through to tool registration.
        path_policy: Filesystem path resolver for every tool that accepts a
            path.
    """

    tbb_root: Path
    path_policy: PathPolicy
    geckodriver_path: Path | None = None
    profile_mode: ProfileMode = "ephemeral"
    profile_path: Path | None = None
    headless: bool = False
    socks_port: int = 9250
    control_port: int = 9251
    tor_data_dir: Path | None = None
    extra_prefs: Mapping[str, Any] = field(default_factory=dict)
    include_legacy_tor_prefs: bool = False
    enabled_caps: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"core", "state", "extract", "diagnostics", "tor", "network-observe"}
        )
    )

    def __post_init__(self) -> None:
        tbb_root = Path(self.tbb_root).expanduser().resolve(strict=False)
        object.__setattr__(self, "tbb_root", tbb_root)

        firefox = tbb_root / _firefox_relative()
        if not firefox.is_file():
            raise DriverConfigError(
                f"tbb_root {tbb_root!s} does not look like a Tor Browser layout: "
                f"expected {firefox!s} to exist"
            )

        tor_bin = tbb_root / _tor_relative()
        if not tor_bin.is_file():
            raise DriverConfigError(
                f"tbb_root {tbb_root!s} is missing the bundled tor binary: "
                f"expected {tor_bin!s} to exist"
            )

        if self.profile_mode == "persistent" and self.profile_path is None:
            raise DriverConfigError(
                "profile_mode='persistent' requires profile_path"
            )
        if self.profile_mode not in ("ephemeral", "persistent"):
            raise DriverConfigError(
                f"profile_mode must be 'ephemeral' or 'persistent', got "
                f"{self.profile_mode!r}"
            )

        if self.socks_port == self.control_port:
            raise DriverConfigError(
                "socks_port and control_port must differ"
            )
        for port_name in ("socks_port", "control_port"):
            value = getattr(self, port_name)
            if not (1 <= value <= 65535):
                raise DriverConfigError(
                    f"{port_name} {value} is outside the valid port range"
                )

        if self.geckodriver_path is not None:
            gp = Path(self.geckodriver_path).expanduser().resolve(strict=False)
            if not gp.is_file():
                raise DriverConfigError(
                    f"geckodriver_path {gp!s} does not exist"
                )
            object.__setattr__(self, "geckodriver_path", gp)

    @property
    def browser_dir(self) -> Path:
        return self.tbb_root / "Browser"

    @property
    def firefox_path(self) -> Path:
        return self.tbb_root / _firefox_relative()

    @property
    def tor_path(self) -> Path:
        return self.tbb_root / _tor_relative()

    @property
    def default_profile_path(self) -> Path:
        return self.browser_dir / "TorBrowser" / "Data" / "Browser" / "profile.default"

    @property
    def tor_data_root(self) -> Path:
        return self.browser_dir / "TorBrowser" / "Data" / "Tor"

    @property
    def geoip_file(self) -> Path:
        return self.tor_data_root / "geoip"

    @property
    def geoip6_file(self) -> Path:
        return self.tor_data_root / "geoip6"

    @property
    def allow_chrome_system_access(self) -> bool:
        """Whether Firefox is launched with ``-remote-allow-system-access``.

        Marionette in Firefox 128+ refuses to switch the WebDriver context
        to ``chrome`` unless the browser was started with this flag. The
        chrome scope is only reachable through tools tagged with the
        ``unsafe`` capability, so the flag is enabled exactly when that
        capability is.
        """

        return "unsafe" in self.enabled_caps
