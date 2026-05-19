"""Stock Tor Browser automation via geckodriver and Marionette.

:class:`TorBrowserDriver` is the entry point. It is used as a context
manager (``with TorBrowserDriver(config) as drv: ...``); the ``__enter__``
launches a bundled tor, starts geckodriver against the supplied Tor
Browser bundle, attaches Marionette, and wires the stem control
connection. ``__exit__`` tears all of that down in reverse order, leaving
the Tor Browser install in the state it was found in. Optional capability
groups (``vision``, ``highlight``, ``tor-routing``, ``unsafe``, ``pdf``,
``http-over-tor``, ``helper-extension``, ``proxy-intercept``) are enabled
by passing ``enabled_caps=frozenset({...})`` to :class:`DriverConfig`, or,
when driving the MCP server, via ``--caps`` (and ``--unsafe``) on the
CLI; only methods tagged with an enabled capability are exposed to
clients.
"""

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
