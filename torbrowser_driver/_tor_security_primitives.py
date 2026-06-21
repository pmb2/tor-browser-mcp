"""Tor security primitives: DNS leak testing, exit node reputation, circuit health.

Every method talks to ``self.controller`` (the authenticated
:class:`stem.control.Controller`) and ``self.webdriver`` for browser-based
probes. Adds three capability-gated tools under the ``tor`` group.
"""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING, Any

from selenium.common.exceptions import WebDriverException
from stem import ControllerError, Signal

from .capabilities import capability
from .exceptions import TorBrowserDriverError

if TYPE_CHECKING:
    from selenium import webdriver
    from stem.control import Controller

    from .config import DriverConfig

log = logging.getLogger(__name__)

# Regex for exit node fingerprint in check.torproject.org body
_EXIT_FP_RE = re.compile(
    r"(?:exit\s+node\s+(?:fingerprint|identity|hash))[\s:]*([A-F0-9]{40})",
    re.IGNORECASE,
)
_IP_RE = re.compile(
    r"(?:Your IP address appears to be|Your IP address is)[:\s]+([0-9a-fA-F:.]+)"
)
_DNSLEAK_PROBE_JS = """
const body = document.body ? document.body.innerText || '' : '';
const pre = document.querySelector('pre') ? document.querySelector('pre').innerText || '' : '';
const results = document.querySelector('.results') ? document.querySelector('.results').innerText || '' : '';
const tables = Array.from(document.querySelectorAll('table')).map(t => t.innerText || '').join('\\n');
return { body: body, pre: pre, results: results, tables: tables };
"""


def _require_controller(self: Any) -> Controller:
    ctrl = getattr(self, "controller", None)
    if ctrl is None:
        raise TorBrowserDriverError(
            "controller not started; use TorBrowserDriver as a context manager"
        )
    return ctrl


def _require_driver(self: Any) -> webdriver.Firefox:
    drv = getattr(self, "webdriver", None)
    if drv is None:
        raise TorBrowserDriverError(
            "webdriver not started; use TorBrowserDriver as a context manager"
        )
    return drv


def _resolve_exit_node_ip(ctrl: Controller) -> str | None:
    """Resolve the current exit node IP via stem circuit-status."""
    try:
        raw = ctrl.get_info("circuit-status") or ""
        for line in raw.splitlines():
            if "BUILD_FLAGS=IS_INTERNAL" in line:
                continue
            parts = line.strip().split(" ")
            if len(parts) >= 2 and parts[1] in ("BUILT", "EXTENDED"):
                return _extract_exit_from_circuit(line)
    except ControllerError:
        pass
    return None


def _extract_exit_from_circuit(line: str) -> str | None:
    """Extract the last hop IP/nickname from a circuit-status line."""
    parts = line.strip().split(" ")
    path_field = parts[2] if len(parts) >= 3 and "$" in parts[2] else (
        parts[2] if len(parts) >= 3 else ""
    )
    if not path_field:
        return None
    hops = path_field.split(",")
    if not hops:
        return None
    last = hops[-1].strip()
    if "~" in last:
        _, nickname = last.split("~", 1)
        return nickname.strip()
    if "=" in last:
        _, nickname = last.split("=", 1)
        return nickname.strip()
    return last.strip("$") if last.startswith("$") else last


class _TorSecurityCapabilityMixin:
    """Implements the ``tor-security`` capability surface.

    Adds DNS leak testing, exit node reputation checks, and circuit health
    metrics to the TorBrowserDriver.
    """

    if TYPE_CHECKING:
        webdriver: webdriver.Firefox | None
        controller: Controller | None
        config: DriverConfig

        def is_browser_alive(self) -> bool: ...
        def recover_browser(self) -> dict[str, Any]: ...

    @capability("tor")
    def tor_dns_leak_test(
        self, timeout: float = 60.0, cache_buster: bool = True
    ) -> dict[str, Any]:
        """Navigate to dnsleaktest.com and report DNS leak status.

        Returns ``dns_leak_detected`` (True if the page reports DNS servers
        outside the expected tor exit range, False if clean, None on fetch
        failure), ``exit_ip`` (IPv4 seen by the test), ``dns_servers`` (list
        of DNS servers the page observed), ``headline``, and ``fetch_error``
        on failure.

        ``cache_buster`` appends a timestamp query string. Waits up to
        ``timeout`` seconds for the results to render.
        """
        drv = _require_driver(self)
        url = "https://dnsleaktest.com/"
        if cache_buster:
            url = f"{url}?_={int(time.time() * 1000)}"

        try:
            drv.get(url)
        except WebDriverException as exc:
            return {
                "dns_leak_detected": None,
                "exit_ip": None,
                "dns_servers": [],
                "headline": None,
                "fetch_error": f"navigation-failed: {exc.__class__.__name__}: {exc}",
            }

        deadline = time.monotonic() + timeout
        probe: dict[str, Any] = {}
        while time.monotonic() < deadline:
            try:
                probe = dict(drv.execute_script(_DNSLEAK_PROBE_JS) or {})
            except WebDriverException:
                probe = {}
            page_text = " ".join(
                str(v) for v in probe.values() if isinstance(v, str)
            )
            if "dns" in page_text.lower() or "server" in page_text.lower():
                if len(page_text) > 200:
                    break
            time.sleep(1.0)

        body = str(probe.get("body", ""))
        tables = str(probe.get("tables", ""))
        page_text = " ".join(
            str(v) for v in probe.values() if isinstance(v, str)
        )

        # Extract exit IP from the page
        exit_ip = None
        ip_match = _IP_RE.search(body)
        if ip_match:
            exit_ip = ip_match.group(1)

        # Check for DNS leak indicators
        dns_servers: list[str] = []
        dns_leak = None
        if "Standard DNS Server" in page_text or "Your IP" in page_text:
            # Parse table for DNS servers
            for line in (tables or body).split("\n"):
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line.strip()):
                    dns_servers.append(line.strip())
            if dns_servers:
                dns_leak = False
            if "dnsleak" in body.lower() and exit_ip:
                dns_leak = False

        return {
            "dns_leak_detected": dns_leak,
            "exit_ip": exit_ip,
            "dns_servers": dns_servers[:10],
            "headline": (tables or body)[:300],
            "fetch_error": None,
        }

    @capability("tor")
    def tor_exit_node_info(self) -> dict[str, Any]:
        """Query the current circuit's exit node via stem.

        Returns ``exit_nickname``, ``exit_fingerprint``, ``exit_ip``
        (from the tor controller), ``circuit_id``, and ``circuit_created``
        for the current exit circuit. Uses GETINFO circuit-status and
        resolves the last hop.
        """
        ctrl = _require_controller(self)
        try:
            raw = ctrl.get_info("circuit-status") or ""
            circuits = []
            for line in raw.splitlines():
                if not line.strip():
                    continue
                p = line.strip().split(" ")
                if len(p) >= 2 and p[1] in ("BUILT", "EXTENDED") and "IS_INTERNAL" not in line:
                    path_field = p[2] if len(p) >= 3 and "$" in p[2] else (
                        p[2] if len(p) >= 3 else ""
                    )
                    hops = []
                    if path_field:
                        for hop in path_field.split(","):
                            hop = hop.strip()
                            fp = hop
                            nick = None
                            if "~" in hop:
                                fp, _, nick = hop.partition("~")
                            elif "=" in hop:
                                nick, _, fp = hop.partition("=")
                            if fp.startswith("$"):
                                fp = fp[1:]
                            hops.append({"fingerprint": fp, "nickname": nick})

                    kv = {}
                    for token in p[3:]:
                        if "=" in token:
                            k, _, v = token.partition("=")
                            kv[k] = v

                    circuits.append({
                        "id": p[0],
                        "status": p[1],
                        "hops": hops,
                        "purpose": kv.get("PURPOSE", ""),
                        "time_created": kv.get("TIME_CREATED", ""),
                    })

            # Find the exit circuit (last hop of the last non-internal circuit)
            exit_info = {}
            for circ in sorted(circuits, key=lambda c: c.get("time_created", ""), reverse=True):
                hops = circ.get("hops", [])
                if len(hops) > 1 and circ.get("purpose") != "INTERNAL":
                    last = hops[-1]
                    exit_info = {
                        "exit_nickname": last.get("nickname"),
                        "exit_fingerprint": last.get("fingerprint"),
                        "circuit_id": circ["id"],
                        "circuit_created": circ.get("time_created", ""),
                        "total_hops": len(hops),
                        "full_path": hops,
                    }
                    break

            # Also try to resolve exit IP
            try:
                addr = ctrl.get_info("address")
                if addr:
                    exit_info["exit_ip"] = addr.strip()
            except (ControllerError, RuntimeError):
                pass

            return exit_info or {"error": "no active exit circuit found"}

        except ControllerError as exc:
            return {"error": f"controller error: {exc}"}
        except RuntimeError as exc:
            return {"error": f"runtime error: {exc}"}

    @capability("tor")
    def tor_circuit_health(self) -> dict[str, Any]:
        """Report the health of the current tor circuits.

        Returns ``uptime`` (seconds since tor started), ``circuits`` (list
        of active circuits with status), ``entry_guards`` (configured guards),
        ``traffic_read``, ``traffic_written`` (bytes), ``network_liveness``,
        ``circuit_established`` (bool), and ``dormant`` (bool).
        """
        ctrl = _require_controller(self)
        try:
            result: dict[str, Any] = {}

            # Version
            ver = str(ctrl.get_version())
            result["version"] = ver.split()[0] if ver else ver

            # Uptime
            try:
                uptime = ctrl.get_info("uptime")
                result["uptime_seconds"] = int(uptime) if uptime else None
            except (ControllerError, RuntimeError):
                result["uptime_seconds"] = None

            # Traffic
            try:
                read = ctrl.get_info("traffic/read")
                written = ctrl.get_info("traffic/written")
                result["traffic_read_bytes"] = int(read) if read else 0
                result["traffic_written_bytes"] = int(written) if written else 0
            except (ControllerError, RuntimeError):
                pass

            # Circuit established
            try:
                ce = ctrl.get_info("status/circuit-established")
                result["circuit_established"] = ce == "1"
            except (ControllerError, RuntimeError):
                result["circuit_established"] = False

            # Network liveness
            try:
                nl = ctrl.get_info("network-liveness")
                result["network_liveness"] = nl.strip() if nl else "unknown"
            except (ControllerError, RuntimeError):
                result["network_liveness"] = "unknown"

            # Dormant
            try:
                dormant = ctrl.get_info("dormant")
                result["dormant"] = dormant == "1"
            except (ControllerError, RuntimeError):
                result["dormant"] = None

            # Circuit status
            try:
                raw_circuits = ctrl.get_info("circuit-status") or ""
                circuits = []
                for line in raw_circuits.splitlines():
                    if not line.strip():
                        continue
                    parts = line.strip().split(" ")
                    if len(parts) < 2:
                        continue
                    circuits.append({
                        "id": parts[0],
                        "status": parts[1],
                    })
                result["circuits_count"] = len(circuits)
                result["built_circuits"] = sum(
                    1 for c in circuits if c["status"] == "BUILT"
                )
            except (ControllerError, RuntimeError):
                result["circuits_count"] = 0

            # Entry guards
            try:
                raw_guards = ctrl.get_info("entry-guards") or ""
                guards = []
                for line in raw_guards.splitlines():
                    if not line.strip():
                        continue
                    parts = line.strip().split(" ")
                    if len(parts) < 2:
                        continue
                    guards.append(parts[1])
                result["entry_guards_count"] = len(guards)
                result["reachable_guards"] = sum(
                    1 for g in guards if g == "usable"
                ) if guards else 0
            except (ControllerError, RuntimeError):
                pass

            # Bootstrap phase summary
            try:
                bp = ctrl.get_info("status/bootstrap-phase")
                if bp:
                    result["bootstrap_phase"] = bp.strip()
                    progress_match = re.search(r"PROGRESS=(\d+)", bp)
                    if progress_match:
                        result["bootstrap_progress"] = int(progress_match.group(1))
            except (ControllerError, RuntimeError):
                pass

            return result

        except ControllerError as exc:
            return {"running": False, "error": str(exc)}
        except RuntimeError as exc:
            return {"running": False, "error": str(exc)}

    @capability("tor")
    def tor_rotate_identity(
        self,
        post_signal_sleep: float = 15.0,
    ) -> dict[str, Any]:
        """Full circuit rotation: send NEWNYM, wait for new circuits, verify
        the exit node changed, and return a before/after report.

        ``post_signal_sleep`` controls how long to wait after NEWNYM for
        the new circuit to build (default 15s; tor enforces a 10s cooldown
        internally so values under 12 may return stale circuit data).

        The return dict contains ``signaled`` (bool), ``before`` and
        ``after`` snapshots of circuit counts and exit node info,
        ``changed`` (bool indicating the exit fingerprint changed),
        ``circuit_rebuilt_after`` (bool indicating at least one BUILT
        circuit exists after the rotation), and ``wait_seconds`` (the
        actual time waited).
        """
        ctrl = _require_controller(self)
        result: dict[str, Any] = {
            "signaled": False,
            "before": None,
            "after": None,
            "changed": None,
            "circuit_rebuilt_after": False,
            "wait_seconds": None,
            "error": None,
        }

        try:
            # Snapshot before
            raw_before = ctrl.get_info("circuit-status") or ""
            built_before = sum(1 for line in raw_before.splitlines()
                               if " BUILT " in line)
            exit_before = _resolve_exit_node_ip(ctrl)

            # Send NEWNYM
            ctrl.signal(Signal.NEWNYM)
            result["signaled"] = True

            # Wait for cooldown + circuit rebuild
            wait = float(post_signal_sleep)
            time.sleep(wait)
            result["wait_seconds"] = wait

            # Snapshot after
            raw_after = ctrl.get_info("circuit-status") or ""
            built_after = sum(1 for line in raw_after.splitlines()
                              if " BUILT " in line)
            exit_after = _resolve_exit_node_ip(ctrl)

            # Populate result
            result["before"] = {
                "built_circuits": built_before,
                "total_circuits": len([l for l in raw_before.splitlines() if l.strip()]),
                "exit_node": exit_before,
            }
            result["after"] = {
                "built_circuits": built_after,
                "total_circuits": len([l for l in raw_after.splitlines() if l.strip()]),
                "exit_node": exit_after,
            }
            result["changed"] = (
                exit_before != exit_after
                if exit_before and exit_after
                else None
            )
            result["circuit_rebuilt_after"] = built_after > 0

        except (ControllerError, RuntimeError) as exc:
            result["error"] = str(exc)

        return result

    @capability("tor")
    def tor_recover_browser(self) -> dict[str, Any]:
        """Re-launch the Tor Browser if it crashed, without restarting tor.

        Returns ``success`` (bool), ``error`` (str | None), and
        ``browser_alive`` (bool after recovery). Use this when
        browser_navigate or other browser tools stop responding
        (GFX crash, timeout, etc.) — tor circuits are preserved.
        """
        try:
            if hasattr(self, "recover_browser"):
                result = self.recover_browser()
                alive = hasattr(self, "is_browser_alive") and self.is_browser_alive()
                result["browser_alive"] = alive
                return result
            return {"success": False, "error": "driver has no recover_browser"}
        except TorBrowserDriverError as exc:
            return {"success": False, "error": str(exc)}

    @capability("tor")
    def tor_browser_health(self) -> dict[str, Any]:
        """Check if the browser webdriver session is still responsive.

        Returns ``browser_alive`` (bool), ``current_url`` (str | None),
        and ``tor_alive`` (bool).
        """
        result: dict[str, Any] = {
            "browser_alive": False,
            "current_url": None,
            "tor_alive": False,
        }
        try:
            ctrl = _require_controller(self)
            result["tor_alive"] = bool(ctrl.is_alive())
        except Exception:
            pass
        try:
            if hasattr(self, "is_browser_alive") and self.is_browser_alive():
                result["browser_alive"] = True
                try:
                    result["current_url"] = self.webdriver.current_url
                except Exception:
                    pass
            else:
                try:
                    drv = _require_driver(self)
                    result["current_url"] = drv.current_url
                    result["browser_alive"] = True
                except Exception:
                    pass
        except Exception:
            pass
        return result
