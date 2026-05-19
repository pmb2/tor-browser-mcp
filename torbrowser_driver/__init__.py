"""Stock Tor Browser automation via geckodriver and Marionette."""

from __future__ import annotations

from .capabilities import (
    DEFAULT_CAPABILITIES,
    KNOWN_CAPABILITIES,
    OPTIONAL_CAPABILITIES,
    capability,
    registered_methods,
)
from .config import DriverConfig
from .driver import TorBrowserDriver
from .exceptions import (
    BrowserLaunchError,
    BrowserTimeoutError,
    DriverConfigError,
    HelperBridgeDisconnected,
    HelperBridgeTimeout,
    HelperExtensionError,
    HelperUnavailable,
    PathNotAllowed,
    ProxyInterceptError,
    TorBootstrapTimeout,
    TorBrowserDriverError,
)
from .path_policy import PathPolicy

try:
    from importlib.metadata import PackageNotFoundError, version as _v

    __version__ = _v("torbrowser-mcp")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    "BrowserLaunchError",
    "BrowserTimeoutError",
    "DEFAULT_CAPABILITIES",
    "DriverConfig",
    "DriverConfigError",
    "HelperBridgeDisconnected",
    "HelperBridgeTimeout",
    "HelperExtensionError",
    "HelperUnavailable",
    "KNOWN_CAPABILITIES",
    "OPTIONAL_CAPABILITIES",
    "PathNotAllowed",
    "PathPolicy",
    "ProxyInterceptError",
    "TorBootstrapTimeout",
    "TorBrowserDriver",
    "TorBrowserDriverError",
    "__version__",
    "capability",
    "registered_methods",
]
