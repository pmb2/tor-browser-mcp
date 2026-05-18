"""Integration smoke for the helper-extension capability.

Exercises the helper-extension WebSocket bridge against a real Tor
Browser + bundled tor. Opt-in: skipped unless ``TBB_ROOT`` points at an
extracted Tor Browser bundle. Set ``GECKODRIVER_PATH`` if geckodriver
is not on ``PATH``. Run with ``pytest -m integration``.

Uses control/SOCKS ports 9256/9257 and bridge port 9258 so it does not
collide with the existing driver smoke (9250/9251), MCP wire smoke
(9252/9253), or optional-caps smoke (9254/9255). Future helper tools
(observation, active routes) grow into this file as they land.
"""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path
from typing import Iterator

import pytest

from torbrowser_driver import (
    DEFAULT_CAPABILITIES,
    DriverConfig,
    PathPolicy,
    TorBrowserDriver,
)


pytestmark = pytest.mark.integration


SOCKS_PORT = 9256
CONTROL_PORT = 9257
BRIDGE_PORT = 9258


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


@pytest.fixture(scope="module")
def drv(
    tbb_root: Path,
    geckodriver_path: Path | None,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[TorBrowserDriver]:
    """Boot one Tor Browser session with helper-extension enabled."""

    base = tmp_path_factory.mktemp("helper-extension-smoke")
    policy = PathPolicy.from_config(output_dir=base / "out", cwd=base)
    config = DriverConfig(
        tbb_root=tbb_root,
        path_policy=policy,
        geckodriver_path=geckodriver_path,
        headless=False,
        socks_port=SOCKS_PORT,
        control_port=CONTROL_PORT,
        helper_bridge_port=BRIDGE_PORT,
        enabled_caps=DEFAULT_CAPABILITIES | {"helper-extension"},
    )

    with TorBrowserDriver(config) as driver:
        yield driver


def _port_is_listening(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((host, port))
        return True
    except (OSError, socket.timeout):
        return False
    finally:
        sock.close()


def test_helper_bridge_connects_and_pings(drv: TorBrowserDriver) -> None:
    """Bridge is up, the extension dialled back, and ping round-trips."""

    bridge = drv._helper_bridge
    assert bridge is not None, "helper bridge should be constructed when cap is enabled"
    assert bridge.connected, "extension should have completed the hello handshake by now"

    response = bridge.request("ping", {}, timeout=5.0)
    assert response.get("ok") is True or "pong" in str(response), (
        f"expected a pong-shaped response, got {response!r}"
    )


def test_helper_bridge_port_freed_on_teardown(
    tbb_root: Path,
    geckodriver_path: Path | None,
    tmp_path: Path,
) -> None:
    """Closing the driver releases the bridge port (no orphan listener)."""

    policy = PathPolicy.from_config(output_dir=tmp_path / "out", cwd=tmp_path)
    teardown_port = BRIDGE_PORT + 100
    config = DriverConfig(
        tbb_root=tbb_root,
        path_policy=policy,
        geckodriver_path=geckodriver_path,
        headless=False,
        socks_port=SOCKS_PORT + 100,
        control_port=CONTROL_PORT + 100,
        helper_bridge_port=teardown_port,
        enabled_caps=DEFAULT_CAPABILITIES | {"helper-extension"},
    )

    with TorBrowserDriver(config) as driver:
        assert driver._helper_bridge is not None
        assert driver._helper_bridge.connected
        assert _port_is_listening("127.0.0.1", teardown_port)

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not _port_is_listening("127.0.0.1", teardown_port):
            return
        time.sleep(0.1)
    pytest.fail(f"bridge port {teardown_port} still listening after driver close")
