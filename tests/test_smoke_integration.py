"""Integration smoke test against a real Tor Browser install.

Opt-in: skipped unless ``TBB_ROOT`` points at an extracted Tor Browser
bundle. Set ``GECKODRIVER_PATH`` if geckodriver is not on ``PATH``. Run
with ``pytest -m integration``.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from stem import Signal

from torbrowser_driver import DriverConfig, PathPolicy, TorBrowserDriver


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def tbb_root() -> Path:
    raw = os.environ.get("TBB_ROOT")
    if not raw:
        pytest.skip("TBB_ROOT not set")
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        pytest.skip(f"TBB_ROOT {root} does not exist")
    return root


@pytest.fixture(scope="module")
def geckodriver_path() -> Path | None:
    raw = os.environ.get("GECKODRIVER_PATH")
    if not raw:
        return None
    p = Path(raw).expanduser().resolve()
    if not p.is_file():
        pytest.skip(f"GECKODRIVER_PATH {p} does not exist")
    return p


def test_boot_check_newnym_teardown(
    tbb_root: Path, geckodriver_path: Path | None, tmp_path: Path
) -> None:
    policy = PathPolicy.from_config(output_dir=tmp_path / "out", cwd=tmp_path)
    config = DriverConfig(
        tbb_root=tbb_root,
        path_policy=policy,
        geckodriver_path=geckodriver_path,
        headless=False,
    )

    with TorBrowserDriver(config) as drv:
        navigated = drv.browser_navigate("about:blank")
        assert navigated["url"].startswith("about:")
        assert drv.browser_title()["title"] == navigated["title"]

        shot = drv.browser_take_screenshot()
        shot_path = Path(shot["path"])
        assert shot_path.is_file()
        assert shot_path.parent == policy.output_dir
        assert shot["bytes"] > 0

        first = drv.check_tor_via_browser(timeout=120.0)
        assert first["is_tor"], f"Tor check did not pass: {first['body_excerpt']!r}"
        assert first["exit_ip"], "no exit IP parsed from check page"

        assert drv.controller is not None
        drv.controller.signal(Signal.NEWNYM)
        time.sleep(12)

        second = first
        for _ in range(4):
            second = drv.check_tor_via_browser(timeout=120.0)
            if second["exit_ip"] and second["exit_ip"] != first["exit_ip"]:
                break
            time.sleep(8)

        assert second["is_tor"]
        assert second["exit_ip"] != first["exit_ip"], (
            f"exit IP did not change after NEWNYM: {first['exit_ip']}"
        )
