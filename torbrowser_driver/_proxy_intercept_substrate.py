"""Embedded mitmproxy substrate for the ``proxy-intercept`` capability.

The substrate runs mitmproxy's ``DumpMaster`` on a daemon thread with
its own asyncio event loop (loop B), separate from the MCP server's
loop (loop A). The public surface is a thread-safe ``ProxyManager``
that starts/stops the daemon, exposes a bounded buffer of serialised
flows recorded by the inline ``FlowRecorder`` addon, and chains
mitmproxy's upstream out through an in-tree HTTP-CONNECT-to-SOCKS5h
adapter so all browser-originated bytes still exit via tor.

This module imports mitmproxy lazily inside ``ProxyManager.start`` so
``import torbrowser_driver`` does not depend on the optional extra.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import pathlib
import queue
import threading
import time
from typing import TYPE_CHECKING, Any, Sequence

from ._proxy_intercept_socks_adapter import SocksHttpConnectAdapter
from .exceptions import ProxyInterceptError


if TYPE_CHECKING:
    from mitmproxy.http import HTTPFlow


log = logging.getLogger(__name__)


_DEFAULT_STOP_TIMEOUT = 10.0
_DEFAULT_START_TIMEOUT = 30.0


class FlowRecorder:
    """mitmproxy addon that serialises flows into a bounded buffer.

    The recorder receives mitmproxy's per-flow hooks
    (``request``/``response``/``error``/``tls_failed_client``) on
    mitmproxy's own event loop (loop B). The buffer is a
    ``collections.deque`` with ``maxlen=max_flows``; older flows are
    evicted automatically when the bound is reached. ``since`` is a
    monotonic integer assigned at insertion under ``_lock`` so callers
    on loop A can use it as a cursor.
    """

    def __init__(self, max_flows: int) -> None:
        if max_flows < 1:
            raise ProxyInterceptError("max_flows must be >= 1")
        self._buffer: collections.deque[dict] = collections.deque(maxlen=max_flows)
        self._lock = threading.Lock()
        self._next = 0
        self._by_id: dict[str, dict] = {}
        self._raw_by_id: dict[str, "HTTPFlow"] = {}

    @property
    def buffer(self) -> Sequence[dict]:
        with self._lock:
            return list(self._buffer)

    @property
    def next_since(self) -> int:
        with self._lock:
            return self._next

    def flow_by_id(self, flow_id: str) -> "HTTPFlow | None":
        """Return the raw ``HTTPFlow`` for ``flow_id`` or ``None``.

        Synthetic entries (e.g. ``tls_failed_client``) have no raw flow
        and return ``None`` even if ``flow_id`` matches a buffer entry.
        """

        with self._lock:
            return self._raw_by_id.get(flow_id)

    def raw_flows_snapshot(self) -> list["HTTPFlow"]:
        """Return raw ``HTTPFlow`` objects in buffer (insertion) order.

        Synthetic entries without a raw flow are skipped.
        """

        with self._lock:
            out: list["HTTPFlow"] = []
            for entry in self._buffer:
                fid = entry.get("id")
                if not isinstance(fid, str):
                    continue
                raw = self._raw_by_id.get(fid)
                if raw is not None:
                    out.append(raw)
            return out

    def raw_ids_snapshot(self) -> set[str]:
        """Return the set of raw-flow ids currently in the buffer."""

        with self._lock:
            return set(self._raw_by_id.keys())

    def clear(self) -> None:
        """Empty the buffer and reset the monotonic cursor to 0."""

        with self._lock:
            self._buffer.clear()
            self._by_id.clear()
            self._raw_by_id.clear()
            self._next = 0

    def request(self, flow: "HTTPFlow") -> None:
        self._record(flow)

    def response(self, flow: "HTTPFlow") -> None:
        self._record(flow)

    def error(self, flow: "HTTPFlow") -> None:
        self._record(flow)

    def tls_failed_client(self, data: Any) -> None:  # noqa: D401 - mitmproxy hook
        try:
            host = getattr(getattr(data, "context", None), "client", None)
            client_repr = repr(host) if host is not None else None
            conn = getattr(data, "conn", None)
            sni = getattr(conn, "sni", None) if conn is not None else None
        except Exception:  # noqa: BLE001
            client_repr = None
            sni = None
        entry = {
            "id": f"tls-failed-{int(time.time() * 1e6)}",
            "request": None,
            "response": None,
            "error": {
                "msg": "tls_failed_client",
                "timestamp": time.time(),
            },
            "server_address": None,
            "tls_failed": {"sni": sni, "client": client_repr},
        }
        self._insert(entry)

    def _record(self, flow: "HTTPFlow") -> None:
        serialised = self._serialise(flow)
        with self._lock:
            self._raw_by_id[serialised["id"]] = flow
            existing = self._by_id.get(serialised["id"])
            if existing is not None:
                preserved_since = existing["since"]
                existing.update(serialised)
                existing["since"] = preserved_since
                return
            self._insert_locked(serialised)

    def _insert(self, entry: dict) -> None:
        with self._lock:
            self._insert_locked(entry)

    def _insert_locked(self, entry: dict) -> None:
        entry["since"] = self._next
        self._next += 1
        if len(self._buffer) == self._buffer.maxlen:
            evicted = self._buffer[0]
            evicted_id = evicted.get("id", "")
            self._by_id.pop(evicted_id, None)
            if isinstance(evicted_id, str):
                self._raw_by_id.pop(evicted_id, None)
        self._buffer.append(entry)
        flow_id = entry.get("id")
        if isinstance(flow_id, str):
            self._by_id[flow_id] = entry

    def _serialise(self, flow: "HTTPFlow") -> dict:
        request = flow.request
        req_dict = {
            "method": request.method,
            "url": request.url,
            "scheme": request.scheme,
            "host": request.host,
            "port": request.port,
            "path": request.path,
            "http_version": request.http_version,
            "headers": [list(item) for item in request.headers.items(multi=True)],
            "timestamp_start": request.timestamp_start,
            "timestamp_end": request.timestamp_end,
        }
        resp_dict: dict | None = None
        response = flow.response
        if response is not None:
            content_length: int | None = None
            raw_cl = response.headers.get("content-length")
            if raw_cl is not None:
                try:
                    content_length = int(raw_cl)
                except ValueError:
                    content_length = None
            if content_length is None and response.raw_content is not None:
                content_length = len(response.raw_content)
            resp_dict = {
                "status_code": response.status_code,
                "reason": response.reason,
                "http_version": response.http_version,
                "headers": [
                    list(item) for item in response.headers.items(multi=True)
                ],
                "timestamp_start": response.timestamp_start,
                "timestamp_end": response.timestamp_end,
                "content_length": content_length,
            }
        err_dict: dict | None = None
        error = flow.error
        if error is not None:
            err_dict = {
                "msg": error.msg,
                "timestamp": error.timestamp,
            }
        server_address: tuple[str, int] | None = None
        server_conn = getattr(flow, "server_conn", None)
        if server_conn is not None:
            addr = getattr(server_conn, "address", None)
            if isinstance(addr, tuple) and len(addr) >= 2:
                try:
                    server_address = (str(addr[0]), int(addr[1]))
                except (TypeError, ValueError):
                    server_address = None
        return {
            "id": flow.id,
            "request": req_dict,
            "response": resp_dict,
            "error": err_dict,
            "server_address": server_address,
        }


class ProxyManager:
    """Lifecycle manager for the intercept daemon thread.

    Owns: one daemon thread (``proxy-intercept``) carrying its own
    asyncio loop, the ``SocksHttpConnectAdapter`` bound to that loop,
    and an embedded mitmproxy ``DumpMaster`` configured to chain
    upstream through that adapter. The public surface is callable from
    the MCP server's loop (loop A); cross-thread interaction uses
    ``asyncio.run_coroutine_threadsafe`` against the daemon's loop.
    """

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        socks_host: str,
        socks_port: int,
        max_flows: int = 1000,
        ca_dir: pathlib.Path | None = None,
    ) -> None:
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._max_flows = max_flows
        self._ca_dir = ca_dir

        self._recorder = FlowRecorder(max_flows)

        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master: Any = None
        self._adapter: SocksHttpConnectAdapter | None = None

        self._state_lock = threading.Lock()
        self._started = False
        self._stopped = False

        self._start_event = threading.Event()
        self._exit_event = threading.Event()
        self._error_queue: queue.Queue[BaseException] = queue.Queue()
        self._last_error: BaseException | None = None
        self._start_error: BaseException | None = None

    @property
    def listen_port(self) -> int:
        return self._listen_port

    @property
    def socks_adapter_port(self) -> int:
        adapter = self._adapter
        if adapter is None:
            raise ProxyInterceptError(
                "socks_adapter_port read before start() succeeded"
            )
        return adapter.actual_port

    @property
    def flow_buffer(self) -> Sequence[dict]:
        """Snapshot of the bounded buffer of serialised flows."""

        return self._recorder.buffer

    @property
    def next_since(self) -> int:
        return self._recorder.next_since

    def flow_by_id(self, flow_id: str) -> Any:
        """Return the raw ``mitmproxy.http.HTTPFlow`` for ``flow_id``.

        ``None`` when the id is unknown or refers to a synthetic
        (no-raw-flow) entry such as a ``tls_failed_client`` record.
        """

        return self._recorder.flow_by_id(flow_id)

    def raw_flows_snapshot(self) -> list[Any]:
        """Snapshot of the buffer's raw ``HTTPFlow`` objects in order."""

        return self._recorder.raw_flows_snapshot()

    def replay_flow(self, flow: Any, timeout: float = 30.0) -> str:
        """Submit ``flow`` to mitmproxy's client replay and wait for completion.

        ``flow`` must be a fresh ``HTTPFlow`` (a deep-copy of a captured
        flow with its own id); the recorder will pick it up under its
        own id and surface it as a new buffer entry. Returns the new
        flow's id once the response has been received.

        Raises :class:`ProxyInterceptError` when the substrate is not
        running, when the replay command fails to dispatch, or when the
        timeout elapses without a completed replay.
        """

        loop = self._loop
        master = self._master
        if loop is None or master is None or not self.is_alive():
            raise ProxyInterceptError(
                "replay_flow called while the substrate is not running"
            )

        flow_id = getattr(flow, "id", None)
        if not isinstance(flow_id, str) or not flow_id:
            raise ProxyInterceptError(
                "replay_flow requires a flow with a string id"
            )

        deadline = time.monotonic() + max(0.0, float(timeout))
        known_ids = self._recorder.raw_ids_snapshot()

        async def _dispatch() -> None:
            master.commands.call("replay.client", [flow])

        future = asyncio.run_coroutine_threadsafe(_dispatch(), loop)
        remaining = max(0.0, deadline - time.monotonic())
        try:
            future.result(timeout=remaining if remaining > 0 else 0.001)
        except Exception as exc:  # noqa: BLE001
            future.cancel()
            raise ProxyInterceptError(
                f"replay dispatch failed: {exc!r}"
            ) from exc

        while True:
            raw = self._recorder.flow_by_id(flow_id)
            if raw is not None and flow_id not in known_ids:
                response = getattr(raw, "response", None)
                error = getattr(raw, "error", None)
                if response is not None or error is not None:
                    return flow_id
            if time.monotonic() >= deadline:
                raise ProxyInterceptError(
                    f"replay did not complete within {timeout:.1f}s"
                )
            time.sleep(0.05)

    def clear_buffer(self) -> int:
        """Empty the recorder buffer; return the count of evicted entries.

        ``buffer`` snapshot + ``clear`` are taken under the recorder's
        lock individually; a flow may race in between, but that race
        is harmless for the count-then-clear semantics callers rely on.
        """

        count = len(self._recorder.buffer)
        self._recorder.clear()
        return count

    def is_alive(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def last_error(self) -> BaseException | None:
        if self._last_error is not None:
            return self._last_error
        try:
            err = self._error_queue.get_nowait()
        except queue.Empty:
            return None
        self._last_error = err
        return err

    def start(self, timeout: float = _DEFAULT_START_TIMEOUT) -> None:
        with self._state_lock:
            if self._started:
                raise ProxyInterceptError("ProxyManager.start() called twice")
            self._started = True

        thread = threading.Thread(
            target=self._run, name="proxy-intercept", daemon=True
        )
        self._thread = thread
        thread.start()

        signalled = self._start_event.wait(timeout)
        if not signalled:
            # Daemon never reached the "listening" point; tear it down.
            self._signal_shutdown()
            thread.join(timeout=_DEFAULT_STOP_TIMEOUT)
            raise ProxyInterceptError(
                f"intercept proxy did not start within {timeout:.1f}s"
            )
        if self._start_error is not None:
            err = self._start_error
            thread.join(timeout=_DEFAULT_STOP_TIMEOUT)
            raise ProxyInterceptError(
                f"intercept proxy failed to start: {err!r}"
            )

    def stop(self, timeout: float = _DEFAULT_STOP_TIMEOUT) -> None:
        """Stop the daemon and tear down the adapter. Idempotent.

        Calling ``stop()`` before ``start()`` is a no-op (logged at
        DEBUG); the manager is considered already stopped.
        """

        with self._state_lock:
            if not self._started:
                log.debug("ProxyManager.stop() called before start(); no-op")
                self._stopped = True
                return
            if self._stopped:
                return
            self._stopped = True

        self._signal_shutdown()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                log.warning(
                    "intercept proxy thread did not exit within %.1fs",
                    timeout,
                )

    def _signal_shutdown(self) -> None:
        loop = self._loop
        master = self._master
        adapter = self._adapter
        if loop is None or not loop.is_running():
            return

        async def _shutdown() -> None:
            try:
                if master is not None:
                    master.shutdown()
            except Exception:  # noqa: BLE001
                log.debug("master.shutdown() raised", exc_info=True)
            try:
                if adapter is not None:
                    await adapter.close()
            except Exception:  # noqa: BLE001
                log.debug("adapter.close() raised", exc_info=True)

        try:
            asyncio.run_coroutine_threadsafe(_shutdown(), loop)
        except RuntimeError:
            log.debug("run_coroutine_threadsafe failed during shutdown", exc_info=True)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._main())
        except BaseException as exc:  # noqa: BLE001
            self._record_error(exc)
        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            except Exception:  # noqa: BLE001
                pass
            try:
                loop.close()
            except Exception:  # noqa: BLE001
                pass
            self._loop = None
            self._exit_event.set()
            if not self._start_event.is_set():
                # start() is still blocked; release it so the caller
                # can observe the failure recorded in _start_error.
                self._start_event.set()

    async def _main(self) -> None:
        try:
            adapter = SocksHttpConnectAdapter(
                listen_host=self._listen_host,
                listen_port=0,
                socks_host=self._socks_host,
                socks_port=self._socks_port,
            )
            await adapter.serve()
            self._adapter = adapter

            master = self._build_master(adapter.actual_port)
            master.addons.add(self._recorder)
            self._master = master
        except BaseException as exc:  # noqa: BLE001
            self._start_error = exc
            self._record_error(exc)
            self._start_event.set()
            adapter = self._adapter
            if adapter is not None:
                try:
                    await adapter.close()
                except Exception:  # noqa: BLE001
                    pass
                self._adapter = None
            return

        self._start_event.set()

        try:
            await master.run()
        except BaseException as exc:  # noqa: BLE001
            self._record_error(exc)
        finally:
            adapter = self._adapter
            self._adapter = None
            if adapter is not None:
                try:
                    await adapter.close()
                except Exception:  # noqa: BLE001
                    pass

    def _build_master(self, adapter_port: int) -> Any:
        from mitmproxy import options as mitm_options
        from mitmproxy.tools.dump import DumpMaster

        opts = mitm_options.Options()
        update_kwargs: dict[str, Any] = {
            "mode": [f"upstream:http://127.0.0.1:{adapter_port}"],
            "listen_host": self._listen_host,
            "listen_port": self._listen_port,
            "ssl_insecure": False,
        }
        if self._ca_dir is not None:
            update_kwargs["confdir"] = str(self._ca_dir)
        if "connection_strategy" in opts.keys():
            update_kwargs["connection_strategy"] = "lazy"
        opts.update(**update_kwargs)
        return DumpMaster(opts, with_termlog=False, with_dumper=False)

    def _record_error(self, exc: BaseException) -> None:
        try:
            self._error_queue.put_nowait(exc)
        except queue.Full:
            pass
        log.debug("intercept proxy thread error: %r", exc, exc_info=True)
