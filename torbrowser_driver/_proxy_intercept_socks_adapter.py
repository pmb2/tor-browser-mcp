"""HTTP CONNECT listener that tunnels via SOCKS5h to the bundled tor.

mitmproxy does not support an upstream SOCKS proxy directly; its
``--mode upstream:...`` flag only accepts HTTP/HTTPS upstreams. This
module supplies the missing piece: an asyncio HTTP/1.1 CONNECT server
that mitmproxy treats as its plain-HTTP upstream proxy, and that
forwards every ``CONNECT host:port`` tunnel into the bundled tor's
SOCKS5 port with ``rdns=True`` so tor performs the DNS lookup. The
adapter is purely an internal hop on 127.0.0.1; it is not reachable
off the loopback interface.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from .exceptions import ProxyInterceptError


log = logging.getLogger(__name__)


# Lazy module-level slot for ``python_socks.async_.asyncio.Proxy``.
# Populated on first dial so ``import torbrowser_driver`` does not depend
# on the optional ``proxy-intercept`` extra. Tests may override this
# attribute directly via ``unittest.mock.patch``.
Proxy: Any = None


def _load_python_socks_proxy() -> Any:
    """Import ``python_socks.async_.asyncio.Proxy`` on first call.

    Caches the resolved class on the module so subsequent calls (and
    ``unittest.mock.patch`` targets) see a populated attribute. Tests
    that pre-patch ``Proxy`` short-circuit the import entirely.
    """

    global Proxy
    if Proxy is None:
        from python_socks.async_.asyncio import Proxy as _ProxyImpl

        Proxy = _ProxyImpl
    return Proxy


_MAX_REQUEST_BYTES = 16 * 1024
_SPLICE_CHUNK = 64 * 1024


class SocksHttpConnectAdapter:
    """asyncio HTTP CONNECT server that tunnels via SOCKS5h to tor.

    Listens on ``listen_host:listen_port`` (typically ``127.0.0.1:0``)
    for HTTP/1.1 ``CONNECT host:port`` requests, opens a ``python-socks``
    SOCKS5 connection to ``socks_host:socks_port`` with ``rdns=True``
    (tor resolves the destination hostname; the adapter never does),
    and bidirectionally splices the streams until either side closes.
    Anything other than CONNECT is rejected with 400; SOCKS handshake
    failures surface as 502.
    """

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        socks_host: str,
        socks_port: int,
    ) -> None:
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._server: Optional[asyncio.base_events.Server] = None
        self._actual_port: int | None = None

    @property
    def actual_port(self) -> int:
        if self._actual_port is None:
            raise ProxyInterceptError(
                "SocksHttpConnectAdapter.actual_port read before serve()"
            )
        return self._actual_port

    async def serve(self) -> None:
        """Bind the listener and return once it is accepting connections."""

        if self._server is not None:
            raise ProxyInterceptError(
                "SocksHttpConnectAdapter.serve() called twice"
            )
        server = await asyncio.start_server(
            self._handle_client,
            host=self._listen_host,
            port=self._listen_port,
        )
        sockets = server.sockets or ()
        if not sockets:
            server.close()
            await server.wait_closed()
            raise ProxyInterceptError(
                "SocksHttpConnectAdapter failed to bind any socket"
            )
        self._actual_port = sockets[0].getsockname()[1]
        self._server = server

    async def close(self) -> None:
        server = self._server
        self._server = None
        if server is None:
            return
        server.close()
        try:
            await server.wait_closed()
        except Exception:  # noqa: BLE001
            log.debug("SocksHttpConnectAdapter close raised", exc_info=True)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await self._serve_one(reader, writer)
        except Exception:  # noqa: BLE001
            log.debug("SocksHttpConnectAdapter client handler raised", exc_info=True)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _serve_one(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        request_line = await self._read_request_line(reader)
        if request_line is None:
            await self._send_status(writer, 400, "Bad Request")
            return
        await self._drain_headers(reader)

        parts = request_line.split(" ")
        if len(parts) != 3:
            await self._send_status(writer, 400, "Bad Request")
            return
        method, target, version = parts
        if method.upper() != "CONNECT":
            await self._send_status(writer, 400, "Bad Request")
            return
        if not version.startswith("HTTP/"):
            await self._send_status(writer, 400, "Bad Request")
            return

        dest = self._parse_authority(target)
        if dest is None:
            await self._send_status(writer, 400, "Bad Request")
            return
        dest_host, dest_port = dest

        from python_socks import (
            ProxyConnectionError,
            ProxyError,
            ProxyTimeoutError,
            ProxyType,
        )

        proxy_cls = _load_python_socks_proxy()
        proxy = proxy_cls(
            proxy_type=ProxyType.SOCKS5,
            host=self._socks_host,
            port=self._socks_port,
            rdns=True,
        )
        try:
            upstream_sock = await proxy.connect(
                dest_host=dest_host, dest_port=dest_port
            )
        except (ProxyConnectionError, ProxyError, ProxyTimeoutError, OSError):
            log.debug(
                "SocksHttpConnectAdapter SOCKS dial failed for %s:%d",
                dest_host,
                dest_port,
                exc_info=True,
            )
            await self._send_status(writer, 502, "Bad Gateway")
            return

        try:
            up_reader, up_writer = await asyncio.open_connection(sock=upstream_sock)
        except Exception:  # noqa: BLE001
            try:
                upstream_sock.close()
            except Exception:  # noqa: BLE001
                pass
            await self._send_status(writer, 502, "Bad Gateway")
            return

        writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            up_writer.close()
            return

        try:
            await asyncio.gather(
                self._splice(reader, up_writer),
                self._splice(up_reader, writer),
                return_exceptions=True,
            )
        finally:
            try:
                up_writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _read_request_line(
        self, reader: asyncio.StreamReader
    ) -> str | None:
        try:
            line = await reader.readuntil(b"\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
            return None
        if len(line) > _MAX_REQUEST_BYTES:
            return None
        try:
            decoded = line[:-2].decode("ascii")
        except UnicodeDecodeError:
            return None
        return decoded

    async def _drain_headers(self, reader: asyncio.StreamReader) -> None:
        total = 0
        while True:
            try:
                line = await reader.readuntil(b"\r\n")
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
                return
            total += len(line)
            if total > _MAX_REQUEST_BYTES:
                return
            if line == b"\r\n":
                return

    def _parse_authority(self, target: str) -> tuple[str, int] | None:
        if not target or ":" not in target:
            return None
        host, _, port_str = target.rpartition(":")
        if not host or not port_str:
            return None
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
            if not host:
                return None
        try:
            port = int(port_str)
        except ValueError:
            return None
        if not (1 <= port <= 65535):
            return None
        return host, port

    async def _send_status(
        self,
        writer: asyncio.StreamWriter,
        code: int,
        reason: str,
    ) -> None:
        payload = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        try:
            writer.write(payload)
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass

    async def _splice(
        self,
        src: asyncio.StreamReader,
        dst: asyncio.StreamWriter,
    ) -> None:
        try:
            while True:
                chunk = await src.read(_SPLICE_CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        except Exception:  # noqa: BLE001
            return
        finally:
            try:
                if dst.can_write_eof():
                    dst.write_eof()
            except Exception:  # noqa: BLE001
                pass
