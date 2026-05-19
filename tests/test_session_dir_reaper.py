"""Tests for the stale session-directory reaper in driver.py."""

from __future__ import annotations

import os
import time
from pathlib import Path

from torbrowser_driver.driver import _reap_stale_session_dirs


def _age(path: Path, seconds: float) -> None:
    now = time.time()
    target = now - seconds
    os.utime(path, (target, target))


def test_reaper_removes_old_session_dirs(tmp_path: Path) -> None:
    old = tmp_path / "torbrowser-driver-old"
    old.mkdir()
    (old / "marker").write_text("x", encoding="utf-8")
    _age(old, 48 * 3600)

    removed = _reap_stale_session_dirs(tempdir=tmp_path, max_age_seconds=24 * 3600)
    assert old in removed
    assert not old.exists()


def test_reaper_leaves_fresh_session_dirs(tmp_path: Path) -> None:
    fresh = tmp_path / "torbrowser-driver-fresh"
    fresh.mkdir()
    removed = _reap_stale_session_dirs(tempdir=tmp_path, max_age_seconds=24 * 3600)
    assert fresh.exists()
    assert fresh not in removed


def test_reaper_ignores_other_entries(tmp_path: Path) -> None:
    unrelated = tmp_path / "some-other-dir"
    unrelated.mkdir()
    _age(unrelated, 48 * 3600)
    removed = _reap_stale_session_dirs(tempdir=tmp_path, max_age_seconds=24 * 3600)
    assert unrelated.exists()
    assert unrelated not in removed


def test_reaper_handles_missing_tempdir_silently(tmp_path: Path) -> None:
    bogus = tmp_path / "does-not-exist"
    removed = _reap_stale_session_dirs(tempdir=bogus, max_age_seconds=0)
    assert removed == []
