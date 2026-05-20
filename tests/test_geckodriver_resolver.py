"""Offline unit tests for the on-first-run geckodriver resolver.

The resolver downloads a geckodriver release archive on cache miss.
These tests never touch the network: every test that exercises the
download path passes a fake ``opener`` that yields archive bytes built
in-memory from a tarfile / zipfile fixture.
"""

from __future__ import annotations

import io
import os
import platform
import tarfile
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from torbrowser_driver import _geckodriver_resolver as resolver_mod
from torbrowser_driver._geckodriver_resolver import (
    _FIREFOX_ESR_TO_GECKODRIVER,
    GeckodriverResolveError,
    _geckodriver_version_for_firefox,
    default_cache_dir,
    resolve_geckodriver,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_app_ini(tbb_root: Path, firefox_version: str) -> None:
    browser = tbb_root / "Browser"
    browser.mkdir(parents=True, exist_ok=True)
    (browser / "application.ini").write_text(
        f"[App]\nVendor=Tor Project\nName=Firefox\nVersion={firefox_version}\n",
        encoding="utf-8",
    )


def _make_tar_gz_archive(binary_basename: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=binary_basename)
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _make_zip_archive(binary_basename: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(binary_basename, payload)
    return buf.getvalue()


class _FakeUrlOpen:
    """Minimal stand-in for :func:`urllib.request.urlopen`.

    The resolver only uses ``response`` as the source argument to
    ``shutil.copyfileobj``, which calls ``.read(n)`` repeatedly until it
    sees an empty bytes. A ``BytesIO`` covers that exactly.
    """

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls: list[str] = []

    def __call__(self, url: str) -> _FakeResponse:
        self.calls.append(url)
        return _FakeResponse(self.payload)


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._buf = io.BytesIO(payload)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        self._buf.close()


def _padded_payload(min_size: int = 300 * 1024) -> bytes:
    return b"#!/usr/bin/env geckodriver\n" + os.urandom(min_size)


# ---------------------------------------------------------------------------
# Static mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("firefox_version", "expected_gecko"),
    [
        ("140.11.0", "0.36.0"),
        ("140.0", "0.36.0"),
        ("128.5.0esr", "0.35.0"),
        ("115.10.0", "0.34.0"),
        ("102.0", "0.32.0"),
        ("91.0", "0.31.0"),
        ("78.0", "0.30.0"),
    ],
)
def test_static_map_matches_known_pairs(firefox_version: str, expected_gecko: str) -> None:
    assert _geckodriver_version_for_firefox(firefox_version) == expected_gecko


def test_static_map_picks_newest_known_for_future_firefox() -> None:
    newest = _FIREFOX_ESR_TO_GECKODRIVER[0][1]
    assert _geckodriver_version_for_firefox("999.0") == newest


def test_static_map_picks_oldest_known_for_pre_ancient_firefox() -> None:
    oldest = _FIREFOX_ESR_TO_GECKODRIVER[-1][1]
    assert _geckodriver_version_for_firefox("60.0") == oldest


def test_static_map_rejects_bogus_version_string() -> None:
    with pytest.raises(GeckodriverResolveError):
        _geckodriver_version_for_firefox("not-a-version")


# ---------------------------------------------------------------------------
# Firefox version detection
# ---------------------------------------------------------------------------


def test_detect_missing_application_ini(tmp_path: Path) -> None:
    (tmp_path / "Browser").mkdir()
    with pytest.raises(GeckodriverResolveError, match=r"application\.ini"):
        resolve_geckodriver(tbb_root=tmp_path, cache_dir=tmp_path / "cache")


def test_detect_application_ini_missing_version_key(tmp_path: Path) -> None:
    browser = tmp_path / "Browser"
    browser.mkdir()
    (browser / "application.ini").write_text("[App]\nName=Firefox\n", encoding="utf-8")
    with pytest.raises(GeckodriverResolveError, match="Version"):
        resolve_geckodriver(tbb_root=tmp_path, cache_dir=tmp_path / "cache")


# ---------------------------------------------------------------------------
# Cache hit / miss
# ---------------------------------------------------------------------------


def test_cache_hit_skips_network(tmp_path: Path) -> None:
    _write_app_ini(tmp_path, "140.11.0")
    cache_dir = tmp_path / "cache"
    binary_name = (
        "geckodriver.exe" if platform.system() == "Windows" else "geckodriver"
    )
    seeded = cache_dir / "0.36.0" / binary_name
    seeded.parent.mkdir(parents=True)
    seeded.write_bytes(b"fake-geckodriver-binary")

    fake = _FakeUrlOpen(b"unused")
    result = resolve_geckodriver(
        tbb_root=tmp_path, cache_dir=cache_dir, opener=fake
    )

    assert result == seeded
    assert fake.calls == []


def test_cache_miss_downloads_extracts_and_caches(tmp_path: Path) -> None:
    _write_app_ini(tmp_path, "140.11.0")
    cache_dir = tmp_path / "cache"
    if platform.system() == "Windows":
        binary_name = "geckodriver.exe"
        archive_bytes = _make_zip_archive(binary_name, _padded_payload())
    else:
        binary_name = "geckodriver"
        archive_bytes = _make_tar_gz_archive(binary_name, _padded_payload())
    fake = _FakeUrlOpen(archive_bytes)

    result = resolve_geckodriver(
        tbb_root=tmp_path, cache_dir=cache_dir, opener=fake
    )

    assert result == cache_dir / "0.36.0" / binary_name
    assert result.is_file()
    assert result.read_bytes().startswith(b"#!/usr/bin/env geckodriver")
    assert len(fake.calls) == 1
    assert "v0.36.0" in fake.calls[0]
    assert fake.calls[0].startswith("https://github.com/mozilla/geckodriver/")
    if os.name == "posix":
        assert result.stat().st_mode & 0o111


def test_cache_miss_then_hit_does_not_redownload(tmp_path: Path) -> None:
    _write_app_ini(tmp_path, "140.11.0")
    cache_dir = tmp_path / "cache"
    if platform.system() == "Windows":
        binary_name = "geckodriver.exe"
        archive_bytes = _make_zip_archive(binary_name, _padded_payload())
    else:
        binary_name = "geckodriver"
        archive_bytes = _make_tar_gz_archive(binary_name, _padded_payload())
    fake = _FakeUrlOpen(archive_bytes)

    first = resolve_geckodriver(tbb_root=tmp_path, cache_dir=cache_dir, opener=fake)
    second = resolve_geckodriver(tbb_root=tmp_path, cache_dir=cache_dir, opener=fake)

    assert first == second
    assert len(fake.calls) == 1


def test_archive_under_minimum_size_is_rejected(tmp_path: Path) -> None:
    _write_app_ini(tmp_path, "140.11.0")
    cache_dir = tmp_path / "cache"
    fake = _FakeUrlOpen(b"tiny-not-an-archive")

    with pytest.raises(GeckodriverResolveError, match="suspiciously small"):
        resolve_geckodriver(tbb_root=tmp_path, cache_dir=cache_dir, opener=fake)
    # On failure the partial archive must not be left behind.
    assert not (cache_dir / "0.36.0").glob("*.part") or list(
        (cache_dir / "0.36.0").glob("*.part")
    ) == []


def test_archive_missing_binary_member_is_rejected(tmp_path: Path) -> None:
    _write_app_ini(tmp_path, "140.11.0")
    cache_dir = tmp_path / "cache"
    if platform.system() == "Windows":
        archive_bytes = _make_zip_archive("README.txt", _padded_payload())
    else:
        archive_bytes = _make_tar_gz_archive("README.txt", _padded_payload())
    fake = _FakeUrlOpen(archive_bytes)

    with pytest.raises(GeckodriverResolveError, match=r"no .* entry"):
        resolve_geckodriver(tbb_root=tmp_path, cache_dir=cache_dir, opener=fake)


# ---------------------------------------------------------------------------
# Default cache directory
# ---------------------------------------------------------------------------


def test_default_cache_dir_is_under_user_cache_home() -> None:
    expected = Path.home() / ".cache" / "tor-browser-mcp" / "geckodriver"
    assert default_cache_dir() == expected


# ---------------------------------------------------------------------------
# Wiring into browser_process._resolve_geckodriver
# ---------------------------------------------------------------------------


def test_resolve_geckodriver_prefers_explicit_path(
    fake_tbb_layout: Path, policy: Any, tmp_path: Path
) -> None:
    from torbrowser_driver import DriverConfig
    from torbrowser_driver.browser_process import _resolve_geckodriver

    explicit = tmp_path / "explicit-geckodriver"
    explicit.write_bytes(b"")
    config = DriverConfig(
        tbb_root=fake_tbb_layout,
        path_policy=policy,
        geckodriver_path=explicit,
    )

    with patch.object(resolver_mod, "resolve_geckodriver") as mocked, patch(
        "torbrowser_driver.browser_process.shutil.which",
        return_value=None,
    ):
        result = _resolve_geckodriver(config)

    assert result == str(explicit)
    mocked.assert_not_called()


def test_resolve_geckodriver_prefers_path_lookup_over_resolver(
    fake_tbb_layout: Path, policy: Any, tmp_path: Path
) -> None:
    from torbrowser_driver import DriverConfig
    from torbrowser_driver.browser_process import _resolve_geckodriver

    path_hit = str(tmp_path / "on-path-geckodriver")
    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)

    with patch.object(resolver_mod, "resolve_geckodriver") as mocked, patch(
        "torbrowser_driver.browser_process.shutil.which",
        return_value=path_hit,
    ):
        result = _resolve_geckodriver(config)

    assert result == path_hit
    mocked.assert_not_called()


def test_resolve_geckodriver_falls_back_to_resolver(
    fake_tbb_layout: Path, policy: Any, tmp_path: Path
) -> None:
    from torbrowser_driver import DriverConfig
    from torbrowser_driver.browser_process import _resolve_geckodriver

    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)
    cached = tmp_path / "resolver-result-geckodriver"
    cached.write_bytes(b"")

    with patch(
        "torbrowser_driver._geckodriver_resolver.resolve_geckodriver",
        return_value=cached,
    ) as mocked, patch(
        "torbrowser_driver.browser_process.shutil.which", return_value=None
    ):
        result = _resolve_geckodriver(config)

    assert result == str(cached)
    mocked.assert_called_once()
    _args, kwargs = mocked.call_args
    assert kwargs["tbb_root"] == config.tbb_root


def test_resolve_geckodriver_translates_resolver_failure(
    fake_tbb_layout: Path, policy: Any
) -> None:
    from torbrowser_driver import DriverConfig
    from torbrowser_driver.browser_process import _resolve_geckodriver
    from torbrowser_driver.exceptions import BrowserLaunchError

    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)

    with patch(
        "torbrowser_driver._geckodriver_resolver.resolve_geckodriver",
        side_effect=GeckodriverResolveError("synthetic failure"),
    ), patch(
        "torbrowser_driver.browser_process.shutil.which", return_value=None
    ), pytest.raises(BrowserLaunchError, match="synthetic failure"):
        _resolve_geckodriver(config)
