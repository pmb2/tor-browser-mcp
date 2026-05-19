"""Per-tab cookie and Web Storage primitives.

These methods implement the ``state`` capability surface: cookies via the
WebDriver cookie jar, ``localStorage`` and ``sessionStorage`` via injected
JavaScript, and a combined storage-state export/import that mirrors the
Playwright shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ._primitive_helpers import (
    _bounded_inline_json,
    _limit_items,
    _write_json_payload,
)
from .capabilities import capability

if TYPE_CHECKING:
    from selenium import webdriver

    from .config import DriverConfig


_SAME_SITE_VALUES = {"Strict", "Lax", "None"}


class _StateCapabilityMixin:
    """Implements the ``state`` capability surface on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: webdriver.Firefox | None
        config: DriverConfig

        def _require_driver(self) -> webdriver.Firefox: ...

    @capability("state")
    def browser_cookie_list(
        self,
        domain: str | None = None,
        path: str | None = None,
        limit: int | None = None,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """List every cookie attached to the current document.

        ``domain`` and ``path`` apply exact-string filters on the cookie's
        ``domain`` and ``path`` fields. ``limit`` caps returned cookies after
        filtering. ``filename`` writes the JSON payload under the output dir
        and returns only artifact metadata.
        """

        drv = self._require_driver()
        cookies = list(drv.get_cookies() or [])
        if domain is not None:
            cookies = [c for c in cookies if c.get("domain") == domain]
        if path is not None:
            cookies = [c for c in cookies if c.get("path") == path]
        total = len(cookies)
        selected, truncated = _limit_items(cookies, limit)
        payload = {
            "cookies": selected,
            "count": len(selected),
            "total": total,
            "truncated": truncated,
        }
        if filename is not None:
            return _write_json_payload(self.config.path_policy, filename, payload)
        return payload

    @capability("state")
    def browser_cookie_get(self, name: str) -> dict[str, Any]:
        """Return the cookie named ``name`` or ``None`` when absent."""

        drv = self._require_driver()
        cookie = drv.get_cookie(name)
        return {"cookie": cookie}

    @capability("state")
    def browser_cookie_set(
        self,
        name: str,
        value: str,
        domain: str | None = None,
        path: str = "/",
        expires: int | None = None,
        http_only: bool = False,
        secure: bool = False,
        same_site: Literal["Strict", "Lax", "None"] | None = None,
    ) -> dict[str, Any]:
        """Add a cookie to the current document's jar.

        ``domain`` is omitted from the WebDriver payload when ``None`` so
        Selenium attaches the cookie to the current document host. ``expires``
        is a Unix timestamp in seconds; when ``None`` the cookie is a session
        cookie. ``same_site`` accepts ``"Strict"``, ``"Lax"``, or ``"None"``.
        """

        drv = self._require_driver()
        cookie: dict[str, Any] = {"name": name, "value": value, "path": path}
        if domain is not None:
            cookie["domain"] = domain
        if expires is not None:
            cookie["expiry"] = int(expires)
        if http_only:
            cookie["httpOnly"] = True
        if secure:
            cookie["secure"] = True
        if same_site is not None:
            if same_site not in _SAME_SITE_VALUES:
                raise ValueError(
                    f"same_site must be one of {sorted(_SAME_SITE_VALUES)}, "
                    f"got {same_site!r}"
                )
            cookie["sameSite"] = same_site
        drv.add_cookie(cookie)
        return {"set": name}

    @capability("state")
    def browser_cookie_delete(self, name: str) -> dict[str, Any]:
        """Delete a single cookie by name from the current document."""

        drv = self._require_driver()
        drv.delete_cookie(name)
        return {"deleted": name}

    @capability("state")
    def browser_cookie_clear(self) -> dict[str, Any]:
        """Delete every cookie attached to the current document."""

        drv = self._require_driver()
        drv.delete_all_cookies()
        return {"cleared": True}

    @capability("state")
    def browser_localstorage_list(
        self,
        limit: int | None = None,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """List keys in ``window.localStorage`` plus entry counts.

        ``limit`` caps returned keys. ``filename`` writes the JSON payload
        under the output dir and returns only artifact metadata.
        """

        drv = self._require_driver()
        keys = list(drv.execute_script("return Object.keys(window.localStorage);") or [])
        total = len(keys)
        selected, truncated = _limit_items(keys, limit)
        payload = {
            "keys": selected,
            "size": total,
            "count": len(selected),
            "total": total,
            "truncated": truncated,
        }
        if filename is not None:
            return _write_json_payload(self.config.path_policy, filename, payload)
        return payload

    @capability("state")
    def browser_localstorage_get(
        self,
        key: str,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Return the ``localStorage`` value for ``key`` (``None`` if absent).

        ``filename`` writes the JSON payload under the output dir and returns
        only artifact metadata.
        """

        drv = self._require_driver()
        value = drv.execute_script(
            "return window.localStorage.getItem(arguments[0]);", key
        )
        payload = {"key": key, "value": value}
        if filename is not None:
            return _write_json_payload(self.config.path_policy, filename, payload)
        return payload

    @capability("state")
    def browser_localstorage_set(self, key: str, value: str) -> dict[str, Any]:
        """Set ``window.localStorage[key] = value``."""

        drv = self._require_driver()
        drv.execute_script(
            "window.localStorage.setItem(arguments[0], arguments[1]);",
            key,
            value,
        )
        return {"set": key}

    @capability("state")
    def browser_localstorage_delete(self, key: str) -> dict[str, Any]:
        """Remove ``key`` from ``window.localStorage``."""

        drv = self._require_driver()
        drv.execute_script(
            "window.localStorage.removeItem(arguments[0]);", key
        )
        return {"deleted": key}

    @capability("state")
    def browser_localstorage_clear(self) -> dict[str, Any]:
        """Clear ``window.localStorage`` for the current origin."""

        drv = self._require_driver()
        drv.execute_script("window.localStorage.clear();")
        return {"cleared": True}

    @capability("state")
    def browser_sessionstorage_list(
        self,
        limit: int | None = None,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """List keys in ``window.sessionStorage`` plus entry counts.

        ``limit`` caps returned keys. ``filename`` writes the JSON payload
        under the output dir and returns only artifact metadata.
        """

        drv = self._require_driver()
        keys = list(drv.execute_script("return Object.keys(window.sessionStorage);") or [])
        total = len(keys)
        selected, truncated = _limit_items(keys, limit)
        payload = {
            "keys": selected,
            "size": total,
            "count": len(selected),
            "total": total,
            "truncated": truncated,
        }
        if filename is not None:
            return _write_json_payload(self.config.path_policy, filename, payload)
        return payload

    @capability("state")
    def browser_sessionstorage_get(
        self,
        key: str,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Return the ``sessionStorage`` value for ``key`` (``None`` if absent).

        ``filename`` writes the JSON payload under the output dir and returns
        only artifact metadata.
        """

        drv = self._require_driver()
        value = drv.execute_script(
            "return window.sessionStorage.getItem(arguments[0]);", key
        )
        payload = {"key": key, "value": value}
        if filename is not None:
            return _write_json_payload(self.config.path_policy, filename, payload)
        return payload

    @capability("state")
    def browser_sessionstorage_set(self, key: str, value: str) -> dict[str, Any]:
        """Set ``window.sessionStorage[key] = value``."""

        drv = self._require_driver()
        drv.execute_script(
            "window.sessionStorage.setItem(arguments[0], arguments[1]);",
            key,
            value,
        )
        return {"set": key}

    @capability("state")
    def browser_sessionstorage_delete(self, key: str) -> dict[str, Any]:
        """Remove ``key`` from ``window.sessionStorage``."""

        drv = self._require_driver()
        drv.execute_script(
            "window.sessionStorage.removeItem(arguments[0]);", key
        )
        return {"deleted": key}

    @capability("state")
    def browser_sessionstorage_clear(self) -> dict[str, Any]:
        """Clear ``window.sessionStorage`` for the current origin."""

        drv = self._require_driver()
        drv.execute_script("window.sessionStorage.clear();")
        return {"cleared": True}

    @capability("state")
    def browser_storage_state(
        self, filename: str | None = None
    ) -> dict[str, Any]:
        """Collect cookies plus local/session storage for the current origin.

        The returned shape mirrors Playwright's storage-state JSON:
        ``{"cookies": [...], "origins": [{"origin", "local_storage", "session_storage"}]}``.
        When ``filename`` is given, the JSON is written under
        :attr:`PathPolicy.output_dir` and the result reports ``path``/``bytes``
        instead. Inline results larger than 512 KiB are replaced by a
        truncation summary; use ``filename`` for large sessions.
        """

        drv = self._require_driver()
        cookies = list(drv.get_cookies() or [])
        origin = drv.execute_script("return window.location.origin;") or ""
        local_entries = drv.execute_script(
            "var s = window.localStorage; var out = [];"
            "for (var i = 0; i < s.length; i++) {"
            "  var k = s.key(i); out.push({name: k, value: s.getItem(k)});"
            "}"
            "return out;"
        ) or []
        session_entries = drv.execute_script(
            "var s = window.sessionStorage; var out = [];"
            "for (var i = 0; i < s.length; i++) {"
            "  var k = s.key(i); out.push({name: k, value: s.getItem(k)});"
            "}"
            "return out;"
        ) or []

        state = {
            "cookies": cookies,
            "origins": [
                {
                    "origin": origin,
                    "local_storage": list(local_entries),
                    "session_storage": list(session_entries),
                }
            ],
        }
        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(state, ensure_ascii=False).encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data)}
        return _bounded_inline_json("storage_state", state)

    @capability("state")
    def browser_set_storage_state(self, filename: str) -> dict[str, Any]:
        """Apply a previously-captured storage state from ``filename``.

        Resolved through :meth:`PathPolicy.resolve_input` (storage-state
        files are produced by :meth:`browser_storage_state` and therefore
        live under the output directory). Cookies are added via
        ``driver.add_cookie``. Local- and session-storage are only applied
        for origins that match the document's current
        ``window.location.origin``; entries for other origins are skipped
        with a reason rather than triggering arbitrary navigations.
        """

        drv = self._require_driver()
        raw_path = Path(filename)
        input_path = raw_path if raw_path.is_absolute() else (
            self.config.path_policy.output_dir / raw_path
        )
        path = self.config.path_policy.resolve_input(input_path)
        raw = path.read_text(encoding="utf-8")
        state = json.loads(raw)

        applied_cookies = 0
        for cookie in state.get("cookies") or []:
            drv.add_cookie(dict(cookie))
            applied_cookies += 1

        current_origin = drv.execute_script("return window.location.origin;") or ""
        applied_origins: list[str] = []
        skipped: list[dict[str, str]] = []

        for entry in state.get("origins") or []:
            origin = entry.get("origin") or ""
            if origin != current_origin:
                skipped.append(
                    {
                        "origin": origin,
                        "reason": (
                            f"current origin is {current_origin!r}; refusing to "
                            "navigate to apply foreign-origin storage"
                        ),
                    }
                )
                continue
            for item in entry.get("local_storage") or []:
                drv.execute_script(
                    "window.localStorage.setItem(arguments[0], arguments[1]);",
                    item.get("name"),
                    item.get("value"),
                )
            for item in entry.get("session_storage") or []:
                drv.execute_script(
                    "window.sessionStorage.setItem(arguments[0], arguments[1]);",
                    item.get("name"),
                    item.get("value"),
                )
            applied_origins.append(origin)

        return {
            "applied": {
                "cookies": applied_cookies,
                "origins": applied_origins,
                "skipped": skipped,
            }
        }
