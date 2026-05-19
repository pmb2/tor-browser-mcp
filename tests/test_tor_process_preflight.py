"""Tests for the port preflight and orphan-detection in tor_process."""

from __future__ import annotations

import socket
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from torbrowser_driver import DriverConfigError, tor_process


def _bind_loopback(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    return sock


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_preflight_passes_when_both_ports_free(tmp_path: Path) -> None:
    tor_exe = tmp_path / "tor.exe"
    tor_exe.write_bytes(b"")
    tor_process.preflight_ports(
        socks_port=_free_port(),
        control_port=_free_port(),
        expected_tor_exe=tor_exe,
    )


def test_preflight_flags_foreign_listener(tmp_path: Path) -> None:
    tor_exe = tmp_path / "tor.exe"
    tor_exe.write_bytes(b"")
    busy = _bind_loopback(0)
    try:
        port = busy.getsockname()[1]
        with pytest.raises(DriverConfigError, match=str(port)):
            tor_process.preflight_ports(
                socks_port=port,
                control_port=_free_port(),
                expected_tor_exe=tor_exe,
            )
    finally:
        busy.close()


def test_preflight_names_both_busy_ports(tmp_path: Path) -> None:
    tor_exe = tmp_path / "tor.exe"
    tor_exe.write_bytes(b"")
    sock_a = _bind_loopback(0)
    sock_b = _bind_loopback(0)
    try:
        port_a = sock_a.getsockname()[1]
        port_b = sock_b.getsockname()[1]
        with pytest.raises(DriverConfigError) as exc_info:
            tor_process.preflight_ports(
                socks_port=port_a,
                control_port=port_b,
                expected_tor_exe=tor_exe,
            )
        message = str(exc_info.value)
        assert str(port_a) in message
        assert str(port_b) in message
    finally:
        sock_a.close()
        sock_b.close()


def test_preflight_reports_same_bundle_orphan(tmp_path: Path) -> None:
    """When the control port is held by our tor exe, the error names the PID."""

    tor_exe = tmp_path / "tor.exe"
    tor_exe.write_bytes(b"")
    busy = _bind_loopback(0)
    try:
        port = busy.getsockname()[1]
        with (
            patch.object(tor_process, "_speaks_tor_control_protocol", return_value=True),
            patch.object(tor_process, "_tcp_listener_pid", return_value=4242),
            patch.object(tor_process, "_process_exe", return_value=tor_exe),
            pytest.raises(DriverConfigError) as exc_info,
        ):
            tor_process.preflight_ports(
                socks_port=_free_port(),
                control_port=port,
                expected_tor_exe=tor_exe,
            )
        message = str(exc_info.value)
        assert "4242" in message
        assert "orphan" in message.lower()
        assert "taskkill" in message.lower() or "kill" in message.lower()
    finally:
        busy.close()


def test_preflight_orphan_no_pid_still_reports_orphan(tmp_path: Path) -> None:
    tor_exe = tmp_path / "tor.exe"
    tor_exe.write_bytes(b"")
    busy = _bind_loopback(0)
    try:
        port = busy.getsockname()[1]
        with (
            patch.object(tor_process, "_speaks_tor_control_protocol", return_value=True),
            patch.object(tor_process, "_tcp_listener_pid", return_value=None),
            patch.object(tor_process, "_process_exe", return_value=None),
            pytest.raises(DriverConfigError) as exc_info,
        ):
            tor_process.preflight_ports(
                socks_port=_free_port(),
                control_port=port,
                expected_tor_exe=tor_exe,
            )
        message = str(exc_info.value)
        assert "orphan" in message.lower()
        assert "pid unknown" in message.lower()
    finally:
        busy.close()


def test_preflight_foreign_tor_does_not_claim_orphan(tmp_path: Path) -> None:
    """If the listener answers control protocol but the exe differs, no orphan claim."""

    tor_exe = tmp_path / "tor.exe"
    tor_exe.write_bytes(b"")
    other_exe = tmp_path / "other-tor.exe"
    other_exe.write_bytes(b"")
    busy = _bind_loopback(0)
    try:
        port = busy.getsockname()[1]
        with (
            patch.object(tor_process, "_speaks_tor_control_protocol", return_value=True),
            patch.object(tor_process, "_tcp_listener_pid", return_value=9999),
            patch.object(tor_process, "_process_exe", return_value=other_exe),
            pytest.raises(DriverConfigError) as exc_info,
        ):
            tor_process.preflight_ports(
                socks_port=_free_port(),
                control_port=port,
                expected_tor_exe=tor_exe,
            )
        message = str(exc_info.value)
        assert "orphan" not in message.lower()
        assert "9999" not in message
    finally:
        busy.close()
