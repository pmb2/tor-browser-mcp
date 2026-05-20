"""Unit tests for ``SocksHttpConnectAdapter``.

The adapter is a localhost-only HTTP/1.1 CONNECT listener that splices
tunnels through a python-socks SOCKS5 proxy. Tests mock the
``python_socks.async_.asyncio.Proxy`` boundary so they do not require
a real SOCKS server, and stand up a pair of asyncio echo servers to
verify bidirectional splice over a real socket pair.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import textwrap
from typing import ClassVar
from unittest.mock import patch

import pytest

from torbrowser_driver._proxy_intercept_socks_adapter import (
    SocksHttpConnectAdapter,
)
from torbrowser_driver.exceptions import ProxyInterceptError


def _run(coro):
    return asyncio.run(coro)


async def _start_adapter(
    socks_host: str = "127.0.0.1",
    socks_port: int = 1,
) -> SocksHttpConnectAdapter:
    adapter = SocksHttpConnectAdapter(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host=socks_host,
        socks_port=socks_port,
    )
    await adapter.serve()
    return adapter


async def _http_request(host: str, port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(payload)
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
    except TimeoutError:
        data = b""
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return data


def test_import_torbrowser_driver_without_python_socks() -> None:
    """``import torbrowser_driver`` must not require python_socks.

    Regression test for the base-install breakage where
    ``_proxy_intercept_socks_adapter`` imported python_socks at module
    top, transitively chained through ``_proxy_intercept_substrate``
    and ``driver.py``, and turned ``import torbrowser_driver`` into a
    hard failure for users who installed without the optional
    ``[proxy-intercept]`` extra. The fix pushes the python_socks (and
    mitmproxy) imports into the call sites that actually dial.

    Runs in a subprocess with the optional extras blocked via
    ``sys.modules[name] = None`` sentinels so the result is independent
    of whether the running test session has already imported them.
    """

    script = textwrap.dedent(
        """
        import sys
        for name in (
            "python_socks",
            "python_socks.async_",
            "python_socks.async_.asyncio",
            "mitmproxy",
            "mitmproxy.http",
            "mitmproxy.tools.dump",
        ):
            sys.modules[name] = None
        import torbrowser_driver
        assert torbrowser_driver.TorBrowserDriver is not None
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"import torbrowser_driver failed without optional extras:\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


def test_actual_port_unset_before_serve() -> None:
    adapter = SocksHttpConnectAdapter(
        listen_host="127.0.0.1",
        listen_port=0,
        socks_host="127.0.0.1",
        socks_port=1,
    )
    with pytest.raises(ProxyInterceptError):
        _ = adapter.actual_port


def test_serve_binds_and_reports_port() -> None:
    async def go():
        adapter = await _start_adapter()
        try:
            assert adapter.actual_port > 0
        finally:
            await adapter.close()

    _run(go())


def test_rejects_non_connect_with_400() -> None:
    async def go():
        adapter = await _start_adapter()
        try:
            return await _http_request(
                "127.0.0.1",
                adapter.actual_port,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
        finally:
            await adapter.close()

    data = _run(go())
    assert data.startswith(b"HTTP/1.1 400 ")


def test_rejects_malformed_request_line_with_400() -> None:
    async def go():
        adapter = await _start_adapter()
        try:
            return await _http_request(
                "127.0.0.1",
                adapter.actual_port,
                b"NOTACONNECT garbage\r\n\r\n",
            )
        finally:
            await adapter.close()

    data = _run(go())
    assert data.startswith(b"HTTP/1.1 400 ")


def test_rejects_malformed_authority_with_400() -> None:
    async def go():
        adapter = await _start_adapter()
        try:
            return await _http_request(
                "127.0.0.1",
                adapter.actual_port,
                b"CONNECT not-a-host-port HTTP/1.1\r\n\r\n",
            )
        finally:
            await adapter.close()

    data = _run(go())
    assert data.startswith(b"HTTP/1.1 400 ")


def test_rejects_invalid_port_with_400() -> None:
    async def go():
        adapter = await _start_adapter()
        try:
            return await _http_request(
                "127.0.0.1",
                adapter.actual_port,
                b"CONNECT example.com:abc HTTP/1.1\r\n\r\n",
            )
        finally:
            await adapter.close()

    data = _run(go())
    assert data.startswith(b"HTTP/1.1 400 ")


def test_double_serve_raises() -> None:
    async def go():
        adapter = await _start_adapter()
        try:
            with pytest.raises(ProxyInterceptError):
                await adapter.serve()
        finally:
            await adapter.close()

    _run(go())


def test_close_is_idempotent() -> None:
    async def go():
        adapter = await _start_adapter()
        await adapter.close()
        await adapter.close()

    _run(go())


class _FakeSocksProxy:
    """Stand-in for python_socks.async_.asyncio.Proxy.

    Records construction kwargs and returns a socket connected to a
    test upstream endpoint on ``.connect(...)``. Per-test subclasses
    set the endpoint to point at a test echo server.
    """

    instances: ClassVar[list[_FakeSocksProxy]] = []
    target_endpoint: tuple[str, int] | None = None
    mode: str = "echo"  # "echo" | "fail"

    def __init__(self, *, proxy_type, host, port, rdns) -> None:
        self.proxy_type = proxy_type
        self.host = host
        self.port = port
        self.rdns = rdns
        self.connect_calls: list[tuple[str, int]] = []
        type(self).instances.append(self)

    async def connect(self, *, dest_host: str, dest_port: int):
        self.connect_calls.append((dest_host, dest_port))
        if type(self).mode == "fail":
            from python_socks import ProxyConnectionError

            raise ProxyConnectionError("simulated SOCKS upstream refused")
        endpoint = type(self).target_endpoint
        assert endpoint is not None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_connect(sock, endpoint)
        return sock


@pytest.fixture(autouse=True)
def _reset_fake_proxy_instances():
    _FakeSocksProxy.instances.clear()
    _FakeSocksProxy.target_endpoint = None
    _FakeSocksProxy.mode = "echo"
    yield
    _FakeSocksProxy.instances.clear()
    _FakeSocksProxy.target_endpoint = None
    _FakeSocksProxy.mode = "echo"


def test_valid_connect_dials_socks_with_rdns() -> None:
    received: list[bytes] = []

    async def go():
        async def upstream_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            data = await reader.read(64)
            received.append(data)
            writer.close()

        upstream = await asyncio.start_server(upstream_handler, "127.0.0.1", 0)
        up_port = upstream.sockets[0].getsockname()[1]
        up_task = asyncio.create_task(upstream.serve_forever())

        _FakeSocksProxy.target_endpoint = ("127.0.0.1", up_port)
        _FakeSocksProxy.mode = "echo"
        try:
            with patch(
                "torbrowser_driver._proxy_intercept_socks_adapter.Proxy",
                _FakeSocksProxy,
            ):
                adapter = SocksHttpConnectAdapter(
                    listen_host="127.0.0.1",
                    listen_port=0,
                    socks_host="10.20.30.40",
                    socks_port=9999,
                )
                await adapter.serve()
                try:
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", adapter.actual_port
                    )
                    writer.write(
                        b"CONNECT example.com:443 HTTP/1.1\r\n"
                        b"Host: example.com:443\r\n\r\n"
                    )
                    await writer.drain()
                    line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                    assert line.startswith(b"HTTP/1.1 200 ")
                    while True:
                        h = await asyncio.wait_for(reader.readline(), timeout=2.0)
                        if h in (b"\r\n", b""):
                            break
                    writer.write(b"hello-upstream")
                    await writer.drain()
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                    for _ in range(40):
                        if received:
                            break
                        await asyncio.sleep(0.05)
                finally:
                    await adapter.close()
        finally:
            up_task.cancel()
            upstream.close()
            try:
                await upstream.wait_closed()
            except Exception:
                pass

    _run(go())

    assert received == [b"hello-upstream"]
    assert _FakeSocksProxy.instances, "fake proxy was not constructed"
    constructed = _FakeSocksProxy.instances[-1]
    assert constructed.host == "10.20.30.40"
    assert constructed.port == 9999
    assert constructed.rdns is True
    assert constructed.connect_calls == [("example.com", 443)]


def test_socks_failure_surfaces_as_502() -> None:
    async def go():
        _FakeSocksProxy.mode = "fail"
        with patch(
            "torbrowser_driver._proxy_intercept_socks_adapter.Proxy",
            _FakeSocksProxy,
        ):
            adapter = SocksHttpConnectAdapter(
                listen_host="127.0.0.1",
                listen_port=0,
                socks_host="127.0.0.1",
                socks_port=1,
            )
            await adapter.serve()
            try:
                return await _http_request(
                    "127.0.0.1",
                    adapter.actual_port,
                    b"CONNECT example.com:443 HTTP/1.1\r\n"
                    b"Host: example.com\r\n\r\n",
                )
            finally:
                await adapter.close()

    data = _run(go())
    assert data.startswith(b"HTTP/1.1 502 ")


def test_bidirectional_splice() -> None:
    """End-to-end byte splice using a real upstream echo server.

    Client writes a payload through the adapter; the fake SOCKS proxy
    transparently routes it to an echo server; the echo server replies
    with the same bytes; the client must see those bytes on the
    inbound half of the splice.
    """

    received: list[bytes] = []

    async def go():
        async def echo(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            data = await reader.read(64)
            received.append(data)
            writer.write(b"echo:" + data)
            await writer.drain()
            writer.close()

        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        echo_task = asyncio.create_task(echo_server.serve_forever())

        _FakeSocksProxy.target_endpoint = ("127.0.0.1", echo_port)
        _FakeSocksProxy.mode = "echo"
        try:
            with patch(
                "torbrowser_driver._proxy_intercept_socks_adapter.Proxy",
                _FakeSocksProxy,
            ):
                adapter = SocksHttpConnectAdapter(
                    listen_host="127.0.0.1",
                    listen_port=0,
                    socks_host="127.0.0.1",
                    socks_port=1,
                )
                await adapter.serve()
                try:
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", adapter.actual_port
                    )
                    writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
                    await writer.drain()
                    line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                    assert line.startswith(b"HTTP/1.1 200 ")
                    while True:
                        h = await asyncio.wait_for(reader.readline(), timeout=2.0)
                        if h in (b"\r\n", b""):
                            break

                    writer.write(b"ping")
                    await writer.drain()
                    reply = await asyncio.wait_for(reader.read(64), timeout=2.0)
                    assert reply == b"echo:ping"
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                finally:
                    await adapter.close()
        finally:
            echo_task.cancel()
            echo_server.close()
            try:
                await echo_server.wait_closed()
            except Exception:
                pass

    _run(go())
    assert received == [b"ping"]
