"""On-first-run geckodriver acquisition keyed to Tor Browser's Firefox ESR.

The driver historically required users to either install a system-wide
``geckodriver`` on ``PATH`` or pass ``--geckodriver-path`` to the MCP
server. Recent Tor Browser releases no longer bundle ``geckodriver``
inside the Linux tarball, so out-of-the-box use needs a fallback that
picks a compatible binary on its own.

This module provides that fallback. Given the path to an extracted Tor
Browser bundle, :func:`resolve_geckodriver`:

1. Reads ``<tbb_root>/Browser/application.ini`` to recover the Firefox
   ESR version Tor Browser is riding.
2. Maps the Firefox ESR major to a known-compatible ``geckodriver``
   version using a static table baked into this module. The map mirrors
   Mozilla's published ``geckodriver`` / Firefox support matrix; the
   most recent entry wins when the major is newer than every known
   entry.
3. Returns the cached binary path if it already exists at
   ``~/.cache/tor-browser-mcp/geckodriver/<version>/<basename>``.
4. Otherwise downloads the release archive from the official
   ``mozilla/geckodriver`` GitHub releases, extracts the binary into
   that cache directory, marks it executable on POSIX, and returns its
   path.

Only the Python standard library is used: :mod:`urllib.request` for
the download, :mod:`tarfile` / :mod:`zipfile` for extraction,
:mod:`pathlib` for layout. There is no checksum or signature
verification beyond a size-sanity check on the downloaded archive; a
hostile network is out of scope for this slice.

Network access is not silent. The resolver logs the URL it is about to
fetch at ``INFO`` before issuing any HTTP request, and only fetches on a
cache miss. Users on air-gapped or hostile networks should pre-populate
the cache directory or pass ``--geckodriver-path`` to bypass the
resolver entirely; both paths skip the network completely.

The cache directory layout is stable and user-visible:

    ~/.cache/tor-browser-mcp/geckodriver/<gecko_version>/
        geckodriver           (POSIX)
        geckodriver.exe       (Windows)

Subsequent sessions reuse the same path without touching the network.
"""

from __future__ import annotations

import configparser
import logging
import os
import platform
import shutil
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

log = logging.getLogger(__name__)


_FIREFOX_ESR_TO_GECKODRIVER: tuple[tuple[int, str], ...] = (
    (140, "0.36.0"),
    (128, "0.35.0"),
    (115, "0.34.0"),
    (102, "0.32.0"),
    (91, "0.31.0"),
    (78, "0.30.0"),
)
"""Static fallback table: Firefox ESR major version → geckodriver version.

Entries are ordered newest first. The resolver picks the largest entry
whose Firefox major is ``<=`` the detected major; an unknown future
Firefox release falls through to the most-recent known entry, which is
the closest compatible build at the time the table was last refreshed.
"""


_GECKODRIVER_RELEASE_URL = (
    "https://github.com/mozilla/geckodriver/releases/download/"
    "v{version}/{archive}"
)


_MIN_ARCHIVE_BYTES = 256 * 1024
"""Size-sanity floor for a downloaded archive (256 KiB).

The smallest real geckodriver release archive is ~1.5 MiB; anything
below this floor is almost certainly an error page, a captive-portal
redirect, or a truncated transfer rather than the binary we wanted.
"""


_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
"""Upper bound on a downloaded archive (64 MiB).

Real geckodriver archives are a few MiB. Anything beyond this is
almost certainly a substituted payload; refuse to extract it.
"""


class GeckodriverResolveError(RuntimeError):
    """Raised when the resolver cannot produce a usable geckodriver path."""


def _detect_firefox_version(tbb_root: Path) -> str:
    """Return ``Version=`` from the bundle's ``Browser/application.ini``."""

    app_ini = tbb_root / "Browser" / "application.ini"
    if not app_ini.is_file():
        raise GeckodriverResolveError(
            f"cannot detect Firefox version: {app_ini!s} does not exist"
        )
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read(app_ini, encoding="utf-8")
    except (OSError, configparser.Error) as exc:
        raise GeckodriverResolveError(
            f"cannot parse {app_ini!s}: {exc}"
        ) from exc
    if not parser.has_option("App", "Version"):
        raise GeckodriverResolveError(
            f"{app_ini!s} has no [App] Version key"
        )
    value = parser.get("App", "Version").strip()
    if not value:
        raise GeckodriverResolveError(
            f"{app_ini!s} [App] Version is empty"
        )
    return value


def _firefox_major(version: str) -> int:
    """Return the leading integer in a Firefox version string."""

    head = version.split(".", 1)[0]
    try:
        return int(head)
    except ValueError as exc:
        raise GeckodriverResolveError(
            f"cannot read Firefox major from version {version!r}"
        ) from exc


def _geckodriver_version_for_firefox(firefox_version: str) -> str:
    """Map a Firefox version to a geckodriver version via the static table."""

    major = _firefox_major(firefox_version)
    for known_major, gecko in _FIREFOX_ESR_TO_GECKODRIVER:
        if major >= known_major:
            return gecko
    return _FIREFOX_ESR_TO_GECKODRIVER[-1][1]


def _platform_archive_descriptor() -> tuple[str, str, str]:
    """Return ``(archive_basename, binary_basename, archive_kind)``.

    ``archive_kind`` is one of ``"tar.gz"`` or ``"zip"``; the resolver's
    extraction step branches on it. ``binary_basename`` is the file the
    archive extracts into, including the ``.exe`` suffix on Windows.
    """

    system = platform.system()
    machine = platform.machine().lower()

    if system == "Linux":
        platform_tag = "linux-aarch64" if machine in ("aarch64", "arm64") else "linux64"
        return f"geckodriver-v{{version}}-{platform_tag}.tar.gz", "geckodriver", "tar.gz"

    if system == "Darwin":
        platform_tag = "macos-aarch64" if machine in ("arm64", "aarch64") else "macos"
        return f"geckodriver-v{{version}}-{platform_tag}.tar.gz", "geckodriver", "tar.gz"

    if system == "Windows":
        platform_tag = "win-aarch64" if machine in ("arm64", "aarch64") else "win64"
        return f"geckodriver-v{{version}}-{platform_tag}.zip", "geckodriver.exe", "zip"

    raise GeckodriverResolveError(
        f"no geckodriver platform mapping for system={system!r} machine={machine!r}"
    )


def default_cache_dir() -> Path:
    """Return ``~/.cache/tor-browser-mcp/geckodriver``.

    The platform-specific cache root is intentionally simple: this
    project ships Linux and Windows support, and the path is documented
    so a user can pre-populate it from an out-of-band channel for
    air-gapped use.
    """

    return Path.home() / ".cache" / "tor-browser-mcp" / "geckodriver"


def _cached_binary_path(cache_dir: Path, version: str, binary_basename: str) -> Path:
    return cache_dir / version / binary_basename


def _download_to(url: str, destination: Path, opener: Callable[[str], object] | None) -> None:
    """Download ``url`` to ``destination``. Caller controls the opener."""

    log.info("fetching geckodriver: %s", url)
    fetcher = opener if opener is not None else urllib.request.urlopen
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(destination.suffix + ".part")
    try:
        with fetcher(url) as response, tmp.open("wb") as out:  # type: ignore[union-attr]
            shutil.copyfileobj(response, out)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    size = tmp.stat().st_size
    if size < _MIN_ARCHIVE_BYTES:
        tmp.unlink(missing_ok=True)
        raise GeckodriverResolveError(
            f"downloaded geckodriver archive is suspiciously small "
            f"({size} bytes < {_MIN_ARCHIVE_BYTES}); refusing to extract"
        )
    if size > _MAX_ARCHIVE_BYTES:
        tmp.unlink(missing_ok=True)
        raise GeckodriverResolveError(
            f"downloaded geckodriver archive is unexpectedly large "
            f"({size} bytes > {_MAX_ARCHIVE_BYTES}); refusing to extract"
        )
    tmp.replace(destination)


def _extract_binary(
    archive_path: Path,
    archive_kind: str,
    binary_basename: str,
    target_dir: Path,
) -> Path:
    """Extract ``binary_basename`` from ``archive_path`` into ``target_dir``.

    Refuses any archive member whose resolved path escapes ``target_dir``
    (defensive against a hostile archive). Returns the absolute path to
    the extracted binary.
    """

    target_dir.mkdir(parents=True, exist_ok=True)
    out_path = target_dir / binary_basename

    if archive_kind == "tar.gz":
        with tarfile.open(archive_path, mode="r:gz") as tar:
            member = None
            for candidate in tar.getmembers():
                if Path(candidate.name).name == binary_basename and candidate.isfile():
                    member = candidate
                    break
            if member is None:
                raise GeckodriverResolveError(
                    f"archive {archive_path!s} contains no {binary_basename!r} entry"
                )
            extracted = tar.extractfile(member)
            if extracted is None:
                raise GeckodriverResolveError(
                    f"could not read {binary_basename!r} from {archive_path!s}"
                )
            with out_path.open("wb") as out:
                shutil.copyfileobj(extracted, out)
    elif archive_kind == "zip":
        with zipfile.ZipFile(archive_path) as zf:
            match = None
            for name in zf.namelist():
                if Path(name).name == binary_basename:
                    match = name
                    break
            if match is None:
                raise GeckodriverResolveError(
                    f"archive {archive_path!s} contains no {binary_basename!r} entry"
                )
            with zf.open(match) as src, out_path.open("wb") as out:
                shutil.copyfileobj(src, out)
    else:
        raise GeckodriverResolveError(
            f"unknown geckodriver archive kind {archive_kind!r}"
        )

    if os.name == "posix":
        mode = out_path.stat().st_mode
        out_path.chmod(mode | 0o111)
    return out_path


def resolve_geckodriver(
    *,
    tbb_root: Path,
    cache_dir: Path | None = None,
    opener: Callable[[str], object] | None = None,
) -> Path:
    """Resolve a geckodriver binary compatible with the given TB bundle.

    Args:
        tbb_root: Root of an extracted Tor Browser bundle.
        cache_dir: Override the default cache directory
            (``~/.cache/tor-browser-mcp/geckodriver``). Mainly useful for
            tests; production callers should accept the default.
        opener: Override :func:`urllib.request.urlopen` for the download
            step. Tests pass a mock that yields archive bytes from a
            fixture file; production callers pass ``None``.

    Returns:
        Absolute path to the cached binary. Subsequent calls with the
        same TB bundle reuse the same path without any network access.

    Raises:
        GeckodriverResolveError: When the Firefox version cannot be
            detected, no platform mapping exists, the download fails the
            size-sanity bound, or the archive does not contain the
            expected binary.
    """

    firefox_version = _detect_firefox_version(tbb_root)
    gecko_version = _geckodriver_version_for_firefox(firefox_version)
    archive_template, binary_basename, archive_kind = _platform_archive_descriptor()
    archive_name = archive_template.format(version=gecko_version)

    cache_root = cache_dir if cache_dir is not None else default_cache_dir()
    cached = _cached_binary_path(cache_root, gecko_version, binary_basename)
    if cached.is_file():
        log.debug(
            "geckodriver cache hit: version=%s path=%s firefox=%s",
            gecko_version,
            cached,
            firefox_version,
        )
        return cached

    url = _GECKODRIVER_RELEASE_URL.format(version=gecko_version, archive=archive_name)
    archive_dir = cache_root / gecko_version
    archive_path = archive_dir / archive_name
    _download_to(url, archive_path, opener)
    try:
        binary_path = _extract_binary(
            archive_path, archive_kind, binary_basename, archive_dir
        )
    finally:
        archive_path.unlink(missing_ok=True)
    log.info(
        "geckodriver cached: version=%s path=%s firefox=%s",
        gecko_version,
        binary_path,
        firefox_version,
    )
    return binary_path
