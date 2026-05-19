"""Tor controller primitives implementing the ``tor`` capability.

Every method talks to ``self.controller`` (the authenticated
:class:`stem.control.Controller` returned by :func:`launch_tor`). The
identity-rotation poll on ``check.torproject.org`` lives here too, since it
is the only ``tor``-capability method that also drives the browser.
"""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING, Any

from selenium.webdriver.common.by import By
from stem import ControllerError, Signal

from ._primitive_helpers import _bounded_inline_json, _limit_items
from .capabilities import capability
from .exceptions import TorBrowserDriverError

if TYPE_CHECKING:
    from selenium import webdriver
    from stem.control import Controller

    from .config import DriverConfig


_IP_RE = re.compile(
    r"(?:Your IP address appears to be|Your IP address is)[:\s]+([0-9a-fA-F:.]+)"
)
_ANY_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


_GETINFO_ALLOWLIST: frozenset[str] = frozenset(
    {
        "version",
        "config-file",
        "config-defaults-file",
        "info/names",
        "events/names",
        "features/names",
        "process/pid",
        "process/uid",
        "process/user",
        "uptime",
        "traffic/read",
        "traffic/written",
        "status/version/current",
        "status/version/recommended",
        "status/circuit-established",
        "status/enough-dir-info",
        "status/good-server-descriptor",
        "status/bootstrap-phase",
        "network-liveness",
        "ns/all",
        "consensus/valid-after",
        "consensus/fresh-until",
        "consensus/valid-until",
        "dormant",
        "fingerprint",
        "address",
        "address-v6",
        "dir/connection-status",
        "circuit-status",
        "stream-status",
        "orconn-status",
        "entry-guards",
        "exit-policy/default",
        "exit-policy/full",
    }
)


def _split_kv_tail(tokens: list[str]) -> dict[str, str]:
    """Parse trailing ``KEY=VALUE`` tokens out of a stem control-line split."""

    out: dict[str, str] = {}
    for token in tokens:
        if "=" in token:
            key, _, value = token.partition("=")
            out[key] = value
    return out


def _parse_circuit_line(line: str) -> dict[str, Any]:
    """Parse one ``circuit-status`` line into a structured dict."""

    parts = line.strip().split(" ")
    if len(parts) < 2:
        return {"raw": line}

    circuit_id = parts[0]
    status = parts[1]
    path_field = parts[2] if len(parts) >= 3 and "$" in parts[2] else ""
    tail = parts[3:] if path_field else parts[2:]

    hops: list[dict[str, str | None]] = []
    if path_field:
        for hop in path_field.split(","):
            hop = hop.strip()
            if not hop:
                continue
            fingerprint = hop
            nickname: str | None = None
            if "~" in hop:
                fingerprint, _, nickname = hop.partition("~")
            elif "=" in hop:
                fingerprint, _, nickname = hop.partition("=")
            if fingerprint.startswith("$"):
                fingerprint = fingerprint[1:]
            hops.append({"fingerprint": fingerprint, "nickname": nickname})

    kv = _split_kv_tail(tail)
    return {
        "id": circuit_id,
        "status": status,
        "path": hops,
        "build_flags": kv.get("BUILD_FLAGS"),
        "purpose": kv.get("PURPOSE"),
        "time_created": kv.get("TIME_CREATED"),
    }


def _parse_stream_line(line: str) -> dict[str, Any]:
    """Parse one ``stream-status`` line into a structured dict."""

    parts = line.strip().split(" ")
    if len(parts) < 4:
        return {"raw": line}
    return {
        "id": parts[0],
        "status": parts[1],
        "circuit_id": parts[2],
        "target": parts[3],
    }


def _parse_guard_line(line: str) -> dict[str, Any]:
    """Parse one ``entry-guards`` line into a structured dict."""

    parts = line.strip().split(" ")
    if len(parts) < 2:
        return {"raw": line}
    head = parts[0]
    fingerprint = head
    nickname: str | None = None
    if "=" in head:
        nickname, _, fingerprint = head.partition("=")
    elif "~" in head:
        nickname, _, fingerprint = head.partition("~")
    if fingerprint.startswith("$"):
        fingerprint = fingerprint[1:]
    return {"fingerprint": fingerprint, "nickname": nickname, "status": parts[1]}


class _TorCapabilityMixin:
    """Implements the ``tor`` capability surface on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: webdriver.Firefox | None
        controller: Controller | None
        config: DriverConfig

        def _require_driver(self) -> webdriver.Firefox: ...

    def _require_controller(self) -> Controller:
        ctrl = getattr(self, "controller", None)
        if ctrl is None:
            raise TorBrowserDriverError(
                "controller not started; use TorBrowserDriver as a context manager"
            )
        return ctrl

    @capability("tor")
    def tor_status(self) -> dict[str, Any]:
        """Report the bundled tor's bootstrap, version, and circuit state.

        Returns ``running: True`` plus ``bootstrap``, ``socks_port``,
        ``control_port``, ``version``, ``circuit_established``, and
        ``is_alive`` when the controller responds. When stem raises
        :class:`ControllerError` the result is ``{"running": False,
        "error": str(exc)}`` so callers can surface a clean diagnostic
        instead of an exception.
        """

        try:
            ctrl = self._require_controller()
            bootstrap = ctrl.get_info("status/bootstrap-phase")
            circuit_established = (
                ctrl.get_info("status/circuit-established") == "1"
            )
            version = str(ctrl.get_version())
            is_alive = bool(ctrl.is_alive())
        except ControllerError as exc:
            return {"running": False, "error": str(exc)}
        except RuntimeError as exc:
            return {"running": False, "error": str(exc)}

        return {
            "running": True,
            "bootstrap": bootstrap,
            "socks_port": int(self.config.socks_port),
            "control_port": int(self.config.control_port),
            "version": version,
            "circuit_established": circuit_established,
            "is_alive": is_alive,
        }

    @capability("tor")
    def tor_check_identity(
        self, timeout: float = 90.0, cache_buster: bool = True
    ) -> dict[str, Any]:
        """Navigate to ``check.torproject.org`` and report routing status.

        Returns ``is_tor`` (``True`` when the page reports the connection
        as Tor), ``exit_ip`` (parsed from the page body when present), and
        ``body_excerpt`` (first ~500 characters of body text for
        debugging). ``cache_buster`` appends a millisecond query string so
        repeated calls do not hit Firefox's cache. The poll waits up to
        ``timeout`` seconds for either ``"Congratulations"`` or ``"Sorry"``
        to appear.
        """

        drv = self._require_driver()
        url = "https://check.torproject.org/"
        if cache_buster:
            url = f"{url}?_={int(time.time() * 1000)}"

        drv.get(url)
        deadline = time.monotonic() + timeout
        body_text = ""
        while time.monotonic() < deadline:
            elements = drv.find_elements(By.TAG_NAME, "body")
            if elements:
                body_text = elements[0].text or ""
                if "Congratulations" in body_text or "Sorry" in body_text:
                    break
            time.sleep(1.0)

        is_tor = "Congratulations" in body_text
        exit_ip: str | None = None
        match = _IP_RE.search(body_text)
        if match:
            exit_ip = match.group(1)
        else:
            any_match = _ANY_IPV4_RE.search(body_text)
            if any_match:
                exit_ip = any_match.group(0)

        return {
            "is_tor": is_tor,
            "exit_ip": exit_ip,
            "body_excerpt": body_text[:500],
        }

    @capability("tor")
    def tor_new_identity(
        self, wait: bool = True, post_signal_sleep: float = 8.0
    ) -> dict[str, Any]:
        """Send NEWNYM to request a fresh tor circuit; tor enforces a
        ten-second cooldown between NEWNYM signals.

        When ``wait`` is true the method sleeps ``post_signal_sleep``
        seconds before returning so subsequent calls do not race the
        cooldown.
        """

        ctrl = self._require_controller()
        ctrl.signal(Signal.NEWNYM)
        waited: float | None = None
        if wait:
            time.sleep(float(post_signal_sleep))
            waited = float(post_signal_sleep)
        return {"signaled": True, "waited": waited}

    @capability("tor")
    def tor_circuit_status(
        self,
        verbose: bool = False,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List the active tor circuits and their relay paths; useful for
        confirming a NEWNYM rotation took effect and for inspecting which
        exit a request is leaving through.

        Each circuit carries ``id``, ``status``, and ``path`` (a list of
        ``{fingerprint, nickname}`` hops). When ``verbose`` is true the
        ``build_flags``, ``purpose``, and ``time_created`` fields are
        included as well. ``limit`` caps returned circuits. Implemented via
        stem's GETINFO circuit-status.
        """

        ctrl = self._require_controller()
        raw = ctrl.get_info("circuit-status") or ""
        circuits: list[dict[str, Any]] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            entry = _parse_circuit_line(line)
            entry.setdefault("purpose", None)
            if not verbose:
                entry.pop("build_flags", None)
                entry.pop("time_created", None)
            circuits.append(entry)
        total = len(circuits)
        selected, truncated = _limit_items(circuits, limit)
        return {
            "circuits": selected,
            "count": len(selected),
            "total": total,
            "truncated": truncated,
        }

    @capability("tor")
    def tor_stream_status(self, limit: int | None = None) -> dict[str, Any]:
        """List the active tor streams and the circuits they are bound to;
        useful for tracing which page request is travelling over which
        circuit.

        Each stream carries ``id``, ``status``, ``circuit_id``, and
        ``target``. ``limit`` caps returned streams. Implemented via stem's
        GETINFO stream-status.
        """

        ctrl = self._require_controller()
        raw = ctrl.get_info("stream-status") or ""
        streams = [
            _parse_stream_line(line)
            for line in raw.splitlines()
            if line.strip()
        ]
        total = len(streams)
        selected, truncated = _limit_items(streams, limit)
        return {
            "streams": selected,
            "count": len(selected),
            "total": total,
            "truncated": truncated,
        }

    @capability("tor")
    def tor_entry_guards(self, limit: int | None = None) -> dict[str, Any]:
        """List the entry guards tor is using to enter the network; useful
        for inspecting which long-lived first-hop relays the current
        session is bound to.

        Each guard is reported as ``{fingerprint, nickname, status}``.
        ``limit`` caps returned guards. Implemented via stem's GETINFO
        entry-guards.
        """

        ctrl = self._require_controller()
        raw = ctrl.get_info("entry-guards") or ""
        guards = [
            _parse_guard_line(line)
            for line in raw.splitlines()
            if line.strip()
        ]
        total = len(guards)
        selected, truncated = _limit_items(guards, limit)
        return {
            "guards": selected,
            "count": len(selected),
            "total": total,
            "truncated": truncated,
        }

    @capability("tor")
    def tor_get_info(
        self,
        keys: list[str],
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Read one or more allowlisted, read-only tor control values for
        diagnostics (version, uptime, traffic counters, and similar) without
        granting arbitrary control-port access.

        ``keys`` must be drawn from a read-only allowlist; any other key
        raises ``ValueError``. The result is ``{"info": {key: value}}``
        with the controller's raw string reply per key. ``filename`` writes
        the JSON payload under the output dir and returns artifact metadata.
        Implemented via stem's GETINFO.
        """

        for key in keys:
            if key not in _GETINFO_ALLOWLIST:
                raise ValueError(
                    f"GETINFO key {key!r} is not in the allowlist; "
                    f"allowed keys: {sorted(_GETINFO_ALLOWLIST)}"
                )
        ctrl = self._require_controller()
        info: dict[str, Any] = {}
        for key in keys:
            info[key] = ctrl.get_info(key)
        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            payload = {"info": info}
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data), "keys": list(info)}
        return _bounded_inline_json("info", info)

    def tor_resolve(self, hostname: str, reverse: bool = False) -> dict[str, Any]:
        """Placeholder for tor DNS resolution; not implemented and not
        exposed as an MCP capability tool. Calling it raises
        :class:`NotImplementedError`.

        Stem's high-level API does not expose a one-call DNS helper, and a
        robust ``RESOLVE`` / reverse ``RESOLVE`` implementation needs to
        listen for an ``ADDRMAP`` event alongside the ``RESOLVE`` command.
        The MCP layer (or a future revision of this driver) is the right
        place for that bookkeeping; until then the method stays as a
        documented placeholder rather than a live tool that would always
        return ``isError=True``.
        """

        raise NotImplementedError(
            "tor_resolve is not implemented; a robust RESOLVE/ADDRMAP "
            "implementation needs event-stream bookkeeping that lives "
            "above this driver layer"
        )
