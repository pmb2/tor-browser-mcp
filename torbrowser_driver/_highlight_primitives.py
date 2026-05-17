"""DOM-overlay primitives implementing the ``highlight`` capability.

These tools tag elements with an inline style for visual debugging by
injecting JavaScript through ``execute_script``. They are designed to be
forgiving: a missing target does not raise, it just reports
``{"highlighted": False}`` so an agent that highlights speculatively can
keep going.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .capabilities import capability

if TYPE_CHECKING:
    from selenium import webdriver

    from .config import DriverConfig


_DEFAULT_HIGHLIGHT_STYLE: dict[str, str] = {
    "outline": "3px solid #ff00ff",
    "outline-offset": "2px",
    "background-color": "rgba(255,255,0,0.2)",
}


_HIGHLIGHT_JS = r"""
const selector = arguments[0];
const style = arguments[1] || {};
const el = document.querySelector(selector);
if (!el) {
    return {found: false};
}
if (!el.hasAttribute('data-tbm-prior-style')) {
    el.setAttribute('data-tbm-prior-style', el.getAttribute('style') || '');
}
for (const key in style) {
    if (Object.prototype.hasOwnProperty.call(style, key)) {
        el.style.setProperty(key, style[key]);
    }
}
return {found: true};
"""


_HIDE_ONE_JS = r"""
const selector = arguments[0];
const el = document.querySelector(selector);
if (!el) {
    return {cleared: 0};
}
if (el.hasAttribute('data-tbm-prior-style')) {
    const prior = el.getAttribute('data-tbm-prior-style');
    if (prior) {
        el.setAttribute('style', prior);
    } else {
        el.removeAttribute('style');
    }
    el.removeAttribute('data-tbm-prior-style');
    return {cleared: 1};
}
return {cleared: 0};
"""


_HIDE_ALL_JS = r"""
const nodes = document.querySelectorAll('[data-tbm-prior-style]');
let count = 0;
nodes.forEach(function (el) {
    const prior = el.getAttribute('data-tbm-prior-style');
    if (prior) {
        el.setAttribute('style', prior);
    } else {
        el.removeAttribute('style');
    }
    el.removeAttribute('data-tbm-prior-style');
    count += 1;
});
return {cleared: count};
"""


class _HighlightCapabilityMixin:
    """Implements the ``highlight`` capability surface on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: "webdriver.Firefox | None"
        config: "DriverConfig"

        def _require_driver(self) -> "webdriver.Firefox": ...

    @capability("highlight")
    def browser_highlight(
        self,
        target: str,
        style: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Apply an inline style overlay to the first element matching ``target``.

        Defaults to a bright magenta outline plus a translucent yellow
        background; pass ``style`` (a CSS-property map) to override. The
        prior inline ``style`` attribute is stashed on the element as
        ``data-tbm-prior-style`` so :meth:`browser_hide_highlight` can
        restore it. Returns ``{"highlighted": False, "selector": target}``
        when no element matches the selector rather than raising.
        """

        drv = self._require_driver()
        applied = dict(_DEFAULT_HIGHLIGHT_STYLE if style is None else style)
        result = drv.execute_script(_HIGHLIGHT_JS, target, applied) or {}
        if not result.get("found"):
            return {"highlighted": False, "selector": target}
        return {"highlighted": True, "selector": target, "applied": applied}

    @capability("highlight")
    def browser_hide_highlight(
        self, target: str | None = None
    ) -> dict[str, Any]:
        """Restore inline styles changed by :meth:`browser_highlight`.

        With ``target`` set, restores that one element's prior style and
        removes the bookkeeping attribute. With ``target`` omitted, walks
        the document for every element carrying ``data-tbm-prior-style``
        and restores each. Returns ``{"cleared": N}`` regardless of mode.
        """

        drv = self._require_driver()
        if target is None:
            result = drv.execute_script(_HIDE_ALL_JS) or {}
        else:
            result = drv.execute_script(_HIDE_ONE_JS, target) or {}
        return {"cleared": int(result.get("cleared", 0))}
