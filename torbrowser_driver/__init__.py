"""Stock Tor Browser automation via geckodriver and Marionette."""

from __future__ import annotations

from .config import DriverConfig
from .driver import TorBrowserDriver
from .exceptions import (
    BrowserLaunchError,
    DriverConfigError,
    PathNotAllowed,
    TorBootstrapTimeout,
    TorBrowserDriverError,
)
from .path_policy import PathPolicy

__version__ = "0.0.0"

__all__ = [
    "BrowserLaunchError",
    "DriverConfig",
    "DriverConfigError",
    "PathNotAllowed",
    "PathPolicy",
    "TorBootstrapTimeout",
    "TorBrowserDriver",
    "TorBrowserDriverError",
    "__version__",
]
