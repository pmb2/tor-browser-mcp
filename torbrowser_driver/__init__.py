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
    DriverConfigError,
    HelperBridgeDisconnected,
    HelperBridgeTimeout,
    HelperExtensionError,
    HelperUnavailable,
    PathNotAllowed,
    TorBootstrapTimeout,
    TorBrowserDriverError,
)
from .path_policy import PathPolicy

__version__ = "0.0.0"

__all__ = [
    "BrowserLaunchError",
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
    "TorBootstrapTimeout",
    "TorBrowserDriver",
    "TorBrowserDriverError",
    "__version__",
    "capability",
    "registered_methods",
]
