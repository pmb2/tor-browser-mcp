"""Shared pytest fixtures for the tor-browser-mcp test suite.

The primitive unit-test files (``test_*_primitives.py``) all construct a
:class:`TorBrowserDriver` without entering its context manager — ``__new__``
bypasses the real launch and the ``webdriver`` attribute is replaced with a
:class:`unittest.mock.MagicMock`. The scaffolding for that construction lives
here so a change to the driver's private attribute set lands in one place
instead of twelve.

The integration-test files (``test_*_smoke_integration.py``) share their
``tbb_root`` and ``geckodriver_path`` fixtures via the same mechanism.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from torbrowser_driver import PathPolicy, TorBrowserDriver
from torbrowser_driver._proxy_intercept_substrate import FlowRecorder


# ---------------------------------------------------------------------------
# Unit-test scaffolding (function scope)
# ---------------------------------------------------------------------------


class _FakeConfig(SimpleNamespace):
    """Minimal stand-in for :class:`DriverConfig` in unit tests.

    Test fixtures that need extra config attributes pass them as kwargs:
    ``_FakeConfig(path_policy=policy, socks_port=9999)``.
    """


@pytest.fixture()
def policy(tmp_path: Path) -> PathPolicy:
    out = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    return PathPolicy.from_config(output_dir=out, cwd=work)


@pytest.fixture()
def drv(policy: PathPolicy) -> TorBrowserDriver:
    """Bare-bones driver with a MagicMock webdriver and no controller.

    Files that need a non-None controller or extra config attributes
    redefine ``drv`` locally; pytest resolves file-local fixtures ahead of
    conftest ones.
    """

    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = _FakeConfig(path_policy=policy)  # type: ignore[assignment]
    instance.webdriver = MagicMock(name="webdriver")
    instance.controller = None
    instance._closed = False
    instance._tor_process = None
    instance._session_dir = None
    instance._owns_session_dir = False
    instance._owns_tor_data_dir = False
    return instance


def _build_fake_tbb_layout(root: Path) -> Path:
    """Populate ``root`` with the file shape ``DriverConfig`` validates against."""

    browser = root / "Browser"
    browser.mkdir(parents=True)
    if platform.system() == "Windows":
        firefox = browser / "firefox.exe"
        tor = browser / "TorBrowser" / "Tor" / "tor.exe"
    else:
        firefox = browser / "firefox"
        tor = browser / "TorBrowser" / "Tor" / "tor"
    tor.parent.mkdir(parents=True)
    firefox.write_bytes(b"")
    tor.write_bytes(b"")
    return root


@pytest.fixture()
def fake_tbb_layout(tmp_path: Path) -> Path:
    """Path to a fake Tor Browser bundle laid out under ``tmp_path``."""

    return _build_fake_tbb_layout(tmp_path / "tbb")


# ---------------------------------------------------------------------------
# Proxy-intercept ProxyManager stand-in
# ---------------------------------------------------------------------------


class _StubProxyManager:
    """Hand-rolled stand-in for :class:`ProxyManager`.

    Covers the observation surface: the recorder buffer, flow lookup,
    aliveness reporting, snapshot/clear. The replay-test file subclasses
    with :meth:`replay_flow` added on top.
    """

    def __init__(
        self,
        *,
        alive: bool = True,
        listen_port: int = 9261,
        max_flows: int = 1000,
        last_error: Exception | None = None,
    ) -> None:
        self._alive = alive
        self.listen_port = listen_port
        self.recorder = FlowRecorder(max_flows=max_flows)
        self._last_error = last_error

    def is_alive(self) -> bool:
        return self._alive

    def last_error(self) -> Exception | None:
        return self._last_error

    @property
    def flow_buffer(self):
        return self.recorder.buffer

    @property
    def next_since(self) -> int:
        return self.recorder.next_since

    def flow_by_id(self, flow_id: str):
        return self.recorder.flow_by_id(flow_id)

    def raw_flows_snapshot(self):
        return self.recorder.raw_flows_snapshot()

    def clear_buffer(self) -> int:
        count = len(self.recorder.buffer)
        self.recorder.clear()
        return count


# ---------------------------------------------------------------------------
# Integration-test fixtures (module scope)
# ---------------------------------------------------------------------------


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
