"""Network-observation primitives implementing the ``network-observe`` capability.

Backed by the browser's Performance API. This layer has no persistent
capture buffer: each call to :meth:`_NetworkObserveCapabilityMixin.browser_network_requests`
re-reads ``performance.getEntriesByType('resource')`` plus the current
navigation entry. The MCP layer can layer a session buffer on top once a
helper-extension capability becomes available; without it, only metadata
visible to ``performance.*`` is captured (no headers, no bodies).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .capabilities import capability

if TYPE_CHECKING:
    from selenium import webdriver

    from .config import DriverConfig


_NETWORK_JS = r"""
function entryToRecord(e) {
  if (!e) return null;
  return {
    url: e.name || null,
    initiator_type: e.initiatorType || (e.entryType === 'navigation' ? 'navigation' : null),
    request_start: e.requestStart != null ? e.requestStart : null,
    response_start: e.responseStart != null ? e.responseStart : null,
    response_end: e.responseEnd != null ? e.responseEnd : null,
    transfer_size: e.transferSize != null ? e.transferSize : null,
    duration: e.duration != null ? e.duration : null,
    decoded_body_size: e.decodedBodySize != null ? e.decodedBodySize : null,
    next_hop_protocol: e.nextHopProtocol || null,
  };
}

var nav = (performance.getEntriesByType('navigation') || []).map(entryToRecord);
var res = (performance.getEntriesByType('resource') || []).map(entryToRecord);
return nav.concat(res).filter(function (e) { return e !== null; });
"""


_API_NOTE = (
    "performance API only; full headers/bodies require helper-extension "
    "or proxy-intercept"
)


class _NetworkObserveCapabilityMixin:
    """Implements the ``network-observe`` capability on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: "webdriver.Firefox | None"
        config: "DriverConfig"

        def _require_driver(self) -> "webdriver.Firefox": ...

    def _collect_network_entries(self) -> list[dict[str, Any]]:
        drv = self._require_driver()
        entries = drv.execute_script(_NETWORK_JS) or []
        return [dict(e) for e in entries]

    @capability("network-observe")
    def browser_network_requests(
        self,
        filter: str | None = None,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """List network entries visible to the Performance API.

        Each entry carries ``url``, ``initiator_type``, ``request_start``,
        ``response_start``, ``response_end``, ``transfer_size``,
        ``duration``, ``decoded_body_size``, and ``next_hop_protocol``.
        ``filter`` is a substring match against ``url``. Only the static
        (Performance-API-derived) view is implemented here. When
        ``filename`` is set, the JSON is written under the output dir.
        """

        entries = self._collect_network_entries()
        if filter is not None:
            needle = filter
            entries = [e for e in entries if needle in str(e.get("url") or "")]

        payload = {
            "requests": entries,
            "count": len(entries),
            "note": _API_NOTE,
        }
        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data), **payload}
        return payload

    @capability("network-observe")
    def browser_network_request(
        self,
        index: int,
        part: str | None = None,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Return the network entry at ``index`` (re-collected each call).

        No buffer is kept between calls; ``index`` is interpreted against
        the result of a fresh ``performance.getEntriesByType`` query, so
        the ordering matches :meth:`browser_network_requests` from the
        same moment in time. ``part`` may be ``None`` (return the entry
        as-is), ``"headers"``, or ``"body"``. Header and body capture are
        not available via the Performance API; for those parts the entry
        metadata is returned alongside ``available: False`` and a reason
        string. ``filename`` writes the resulting JSON to disk.
        """

        entries = self._collect_network_entries()
        if not entries:
            raise IndexError("no network entries available")
        if index < -len(entries) or index >= len(entries):
            raise IndexError(
                f"network entry index {index} out of range (have {len(entries)})"
            )
        entry = entries[index]

        if part is None:
            payload: dict[str, Any] = dict(entry)
        elif part in ("headers", "body"):
            payload = {
                "available": False,
                "reason": (
                    "headers/body capture requires helper-extension "
                    "or proxy-intercept"
                ),
                "entry": entry,
            }
        else:
            raise ValueError(
                f"part must be None, 'headers', or 'body'; got {part!r}"
            )

        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data), **payload}
        return payload
