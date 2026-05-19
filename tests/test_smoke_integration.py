"""Integration smoke test against a real Tor Browser install.

Opt-in: skipped unless ``TBB_ROOT`` points at an extracted Tor Browser
bundle. Set ``GECKODRIVER_PATH`` if geckodriver is not on ``PATH``. Run
with ``pytest -m integration``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from torbrowser_driver import DriverConfig, PathPolicy, TorBrowserDriver

pytestmark = pytest.mark.integration


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

        status = drv.tor_status()
        assert status["running"] is True
        assert status["circuit_established"] is True

        circuits = drv.tor_circuit_status()
        assert isinstance(circuits["circuits"], list)

        first = drv.tor_check_identity(timeout=120.0)
        assert first["is_tor"], f"Tor check did not pass: {first['body_excerpt']!r}"
        assert first["exit_ip"], "no exit IP parsed from check page"

        metadata = drv.browser_extract_metadata()
        assert "meta" in metadata

        dump = drv.browser_dump_page()
        for artifact_path in dump["artifacts"].values():
            assert Path(artifact_path).is_file()

        drv.tor_new_identity(wait=True, post_signal_sleep=12.0)

        second = first
        for _ in range(4):
            second = drv.tor_check_identity(timeout=120.0)
            if second["exit_ip"] and second["exit_ip"] != first["exit_ip"]:
                break
            drv.tor_new_identity(wait=True, post_signal_sleep=8.0)

        assert second["is_tor"]
        assert second["exit_ip"] != first["exit_ip"], (
            f"exit IP did not change after NEWNYM: {first['exit_ip']}"
        )
