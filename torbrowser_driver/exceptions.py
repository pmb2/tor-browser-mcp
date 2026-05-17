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
