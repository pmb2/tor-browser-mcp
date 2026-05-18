"""Exceptions raised by the Tor Browser driver library."""

from __future__ import annotations


class TorBrowserDriverError(Exception):
    """Base class for every error raised by this package."""


class PathNotAllowed(TorBrowserDriverError):
    """A path or file:// URL was rejected by the filesystem path policy."""


class DriverConfigError(TorBrowserDriverError):
    """A :class:`DriverConfig` value is invalid or inconsistent."""


class TorBootstrapTimeout(TorBrowserDriverError):
    """The bundled tor process did not finish bootstrapping in time."""


class BrowserLaunchError(TorBrowserDriverError):
    """Geckodriver or Tor Browser failed to start."""


class HelperExtensionError(TorBrowserDriverError):
    """Base class for helper-extension capability failures."""


class HelperBridgeTimeout(HelperExtensionError):
    """A request to the helper extension did not get a response in time."""


class HelperBridgeDisconnected(HelperExtensionError):
    """The helper-extension bridge connection is no longer alive."""


class HelperUnavailable(HelperExtensionError):
    """A tool requires a helper-extension feature this Firefox build does not support."""


class ProxyInterceptError(TorBrowserDriverError):
    """Raised when the proxy-intercept substrate fails to start or operate."""
