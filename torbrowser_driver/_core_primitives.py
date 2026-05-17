"""Per-tab driver primitives surfaced as the ``core`` capability.

These methods sit directly on :class:`TorBrowserDriver` via mixin
inheritance. They are deliberately thin wrappers over Selenium so the MCP
layer can register them as tools without translating types. Each returns a
JSON-serialisable ``dict[str, Any]``; failures raise (no ``status: "error"``
return shapes).
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

from selenium.common.exceptions import (
    NoAlertPresentException,
    NoSuchElementException,
)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait

from .capabilities import capability
from .exceptions import PathNotAllowed, TorBrowserDriverError

if TYPE_CHECKING:
    from selenium import webdriver

    from .config import DriverConfig


_PAGE_SOURCE_INLINE_CAP = 1_048_576  # 1 MB
_TEXT_READ_INLINE_CAP = 262_144  # 256 KB


_SNAPSHOT_JS = r"""
const root = arguments[0] || document.documentElement;
const maxDepth = arguments[1] | 0;
const includeBoxes = !!arguments[2];

function inferRole(el) {
  const explicit = el.getAttribute && el.getAttribute('role');
  if (explicit) return explicit;
  const tag = (el.tagName || '').toLowerCase();
  const roleByTag = {
    a: el.hasAttribute && el.hasAttribute('href') ? 'link' : null,
    button: 'button',
    h1: 'heading', h2: 'heading', h3: 'heading',
    h4: 'heading', h5: 'heading', h6: 'heading',
    input: (function () {
      const t = (el.getAttribute('type') || 'text').toLowerCase();
      if (t === 'checkbox') return 'checkbox';
      if (t === 'radio') return 'radio';
      if (t === 'submit' || t === 'button') return 'button';
      return 'textbox';
    })(),
    textarea: 'textbox',
    select: 'combobox',
    img: 'img',
    nav: 'navigation',
    main: 'main',
    header: 'banner',
    footer: 'contentinfo',
    form: 'form',
    ul: 'list',
    ol: 'list',
    li: 'listitem',
  };
  return roleByTag[tag] || null;
}

function accessibleName(el) {
  if (!el || !el.getAttribute) return null;
  const aria = el.getAttribute('aria-label');
  if (aria) return aria.trim();
  const labelledBy = el.getAttribute('aria-labelledby');
  if (labelledBy) {
    const parts = labelledBy.split(/\s+/)
      .map(id => document.getElementById(id))
      .filter(Boolean)
      .map(n => (n.textContent || '').trim())
      .filter(Boolean);
    if (parts.length) return parts.join(' ');
  }
  const tag = (el.tagName || '').toLowerCase();
  if (tag === 'img') {
    const alt = el.getAttribute('alt');
    if (alt) return alt.trim();
  }
  if (tag === 'input' || tag === 'textarea' || tag === 'select') {
    const value = el.value;
    if (value) return String(value);
    const placeholder = el.getAttribute('placeholder');
    if (placeholder) return placeholder;
  }
  if (tag === 'button' || tag === 'a') {
    const text = (el.textContent || '').trim();
    if (text) return text.slice(0, 200);
  }
  return null;
}

function visibleText(el) {
  if (!el) return null;
  if (el.nodeType === 3) {
    const t = (el.textContent || '').trim();
    return t || null;
  }
  const direct = Array.from(el.childNodes || [])
    .filter(n => n.nodeType === 3)
    .map(n => (n.textContent || '').trim())
    .filter(Boolean)
    .join(' ');
  return direct || null;
}

function walk(el, depth) {
  if (!el || el.nodeType !== 1) return null;
  const node = {
    tag: (el.tagName || '').toLowerCase(),
    role: inferRole(el),
    name: accessibleName(el),
    text: visibleText(el),
    children: [],
  };
  if (includeBoxes && typeof el.getBoundingClientRect === 'function') {
    const r = el.getBoundingClientRect();
    node.bounds = { x: r.x, y: r.y, w: r.width, h: r.height };
  } else {
    node.bounds = null;
  }
  if (depth > 0) {
    const kids = el.children || [];
    for (let i = 0; i < kids.length; i++) {
      const child = walk(kids[i], depth - 1);
      if (child) node.children.push(child);
    }
  }
  return node;
}

return walk(root, maxDepth);
"""


_MODIFIER_KEYS = {
    "CTRL": Keys.CONTROL,
    "CONTROL": Keys.CONTROL,
    "SHIFT": Keys.SHIFT,
    "ALT": Keys.ALT,
    "META": Keys.META,
    "COMMAND": Keys.COMMAND,
}


class _CoreCapabilityMixin:
    """Implements the ``core`` capability surface on :class:`TorBrowserDriver`.

    Every method assumes :class:`TorBrowserDriver` was entered as a context
    manager; calling against an un-started driver raises
    :class:`RuntimeError`.
    """

    if TYPE_CHECKING:
        webdriver: "webdriver.Firefox | None"
        config: "DriverConfig"

    def _require_driver(self) -> "webdriver.Firefox":
        drv = getattr(self, "webdriver", None)
        if drv is None:
            raise RuntimeError(
                "driver not started; use TorBrowserDriver as a context manager"
            )
        return drv

    def _find(self, selector: str):
        drv = self._require_driver()
        return drv.find_element(By.CSS_SELECTOR, selector)

    @capability("core")
    def browser_navigate(self, url: str) -> dict[str, Any]:
        """Navigate the current tab to ``url``.

        ``file://`` URLs are rejected unless the resolved local path is
        inside the configured :class:`PathPolicy`. Returns the final
        ``current_url`` (which may differ from ``url`` after redirects) and
        the document title.
        """

        drv = self._require_driver()
        if url.lower().startswith("file:") and not self.config.path_policy.is_file_url_allowed(url):
            raise PathNotAllowed(f"file:// URL not allowed: {url}")
        drv.get(url)
        return {"url": drv.current_url, "title": drv.title}

    @capability("core")
    def browser_navigate_back(self) -> dict[str, Any]:
        """Step one entry back in the current tab's history."""

        drv = self._require_driver()
        drv.back()
        return {"url": drv.current_url}

    @capability("core")
    def browser_navigate_forward(self) -> dict[str, Any]:
        """Step one entry forward in the current tab's history."""

        drv = self._require_driver()
        drv.forward()
        return {"url": drv.current_url}

    @capability("core")
    def browser_reload(self) -> dict[str, Any]:
        """Reload the current tab."""

        drv = self._require_driver()
        drv.refresh()
        return {"url": drv.current_url}

    @capability("core")
    def browser_close(self) -> dict[str, Any]:
        """Close the current tab (not the whole driver session).

        The driver context manager handles full shutdown; this just calls
        ``driver.close()`` on the active window. If a remaining window is
        present, focus switches to it.
        """

        drv = self._require_driver()
        closed = drv.current_window_handle
        drv.close()
        remaining = drv.window_handles
        if remaining:
            drv.switch_to.window(remaining[0])
        return {"closed": closed, "remaining": list(remaining)}

    @capability("core")
    def browser_current_url(self) -> dict[str, Any]:
        """Return the current tab's URL."""

        drv = self._require_driver()
        return {"url": drv.current_url}

    @capability("core")
    def browser_title(self) -> dict[str, Any]:
        """Return the current document title."""

        drv = self._require_driver()
        return {"title": drv.title}

    @capability("core")
    def browser_page_source(
        self, filename: str | None = None
    ) -> dict[str, Any]:
        """Return ``driver.page_source`` inline, or write it to ``filename``.

        Inline mode is capped at 1 MiB; when the source exceeds that the
        returned ``source`` is truncated and ``truncated`` is ``True``. Use
        the file-mode variant for large pages.
        """

        drv = self._require_driver()
        source = drv.page_source or ""
        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = source.encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data)}
        encoded = source.encode("utf-8")
        if len(encoded) > _PAGE_SOURCE_INLINE_CAP:
            truncated = encoded[:_PAGE_SOURCE_INLINE_CAP].decode("utf-8", errors="ignore")
            return {"source": truncated, "truncated": True}
        return {"source": source, "truncated": False}

    @capability("core")
    def browser_snapshot(
        self,
        selector: str | None = None,
        depth: int = 8,
        boxes: bool = False,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Return a JS-built approximation of the page's accessibility tree.

        Each node carries ``tag``, ``role``, ``name``, ``text``, optional
        ``bounds`` (when ``boxes=True``), and ``children``. Role and name
        are inferred from a small set of ARIA attributes and tag heuristics,
        so this is **not** equivalent to a true accessibility-tree
        snapshot - it is a cheap, transport-safe summary built via
        ``execute_script``. When ``filename`` is given the JSON is written
        to disk under :attr:`PathPolicy.output_dir`.
        """

        drv = self._require_driver()
        root_el = self._find(selector) if selector else None
        tree = drv.execute_script(_SNAPSHOT_JS, root_el, int(depth), bool(boxes))
        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(tree, ensure_ascii=False).encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data)}
        return {"snapshot": tree}

    @capability("core")
    def browser_take_screenshot(
        self,
        selector: str | None = None,
        full_page: bool = False,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Capture a PNG screenshot and write it under the output dir.

        With ``selector`` set, the screenshot is scoped to the matched
        element. Otherwise ``full_page=True`` uses Firefox's full-page
        capture when the Selenium build exposes it, falling back to a
        viewport screenshot. ``filename`` defaults to a millisecond-stamped
        ``screenshot-<ts>.png``. Screenshots are always written to disk -
        the result dict carries the path and byte count, never inline
        base64.
        """

        drv = self._require_driver()
        if selector is not None:
            element = self._find(selector)
            png = element.screenshot_as_png
        elif full_page and hasattr(drv, "get_full_page_screenshot_as_png"):
            png = drv.get_full_page_screenshot_as_png()
        else:
            png = drv.get_screenshot_as_png()

        if filename is None:
            filename = f"screenshot-{int(time.time() * 1000)}.png"
        path = self.config.path_policy.resolve_output(filename)
        path.write_bytes(png)
        return {"path": str(path), "bytes": len(png)}

    @capability("core")
    def browser_wait_for(
        self,
        text: str | None = None,
        text_gone: str | None = None,
        selector: str | None = None,
        time_s: float | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Wait for one of: a body-text match, a body-text disappearance,
        an element to be present, or a fixed sleep.

        Exactly one of ``text``, ``text_gone``, ``selector``, ``time_s``
        must be set; passing zero or more than one raises ``ValueError``.
        The text and selector modes raise the built-in ``TimeoutError`` when
        ``timeout`` elapses without a match. Returns the mode that ran and
        the elapsed wall-clock seconds.
        """

        provided = [n for n, v in (
            ("text", text),
            ("text_gone", text_gone),
            ("selector", selector),
            ("time_s", time_s),
        ) if v is not None]
        if len(provided) != 1:
            raise ValueError(
                f"browser_wait_for needs exactly one mode argument; got {provided}"
            )

        drv = self._require_driver()
        start = time.monotonic()

        if time_s is not None:
            time.sleep(float(time_s))
            return {"waited": "time_s", "elapsed": time.monotonic() - start}

        if selector is not None:
            try:
                WebDriverWait(drv, timeout).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                )
            except Exception as exc:
                raise TimeoutError(
                    f"selector {selector!r} did not appear within {timeout}s"
                ) from exc
            return {"waited": "selector", "elapsed": time.monotonic() - start}

        deadline = start + timeout
        needle = text if text is not None else text_gone
        want_present = text is not None
        while True:
            body_text = ""
            elements = drv.find_elements(By.TAG_NAME, "body")
            if elements:
                body_text = elements[0].text or ""
            present = needle in body_text
            if want_present and present:
                return {"waited": "text", "elapsed": time.monotonic() - start}
            if (not want_present) and (not present):
                return {"waited": "text_gone", "elapsed": time.monotonic() - start}
            if time.monotonic() >= deadline:
                mode = "text" if want_present else "text_gone"
                raise TimeoutError(
                    f"body text condition ({mode}={needle!r}) not met within {timeout}s"
                )
            time.sleep(0.25)

    @capability("core")
    def browser_click(
        self,
        target: str,
        double: bool = False,
        button: str = "left",
        modifiers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Click the first element matching ``target``.

        ``button="right"`` performs a context-click; ``double=True`` issues
        a double-click via ``ActionChains``. ``modifiers`` accepts a list of
        ``"CTRL"``/``"SHIFT"``/``"ALT"``/``"META"`` (case-insensitive) that
        are held for the duration of the click.
        """

        drv = self._require_driver()
        element = self._find(target)
        actions = ActionChains(drv)
        held: list[str] = []
        if modifiers:
            for mod in modifiers:
                key = _MODIFIER_KEYS.get(mod.upper())
                if key is None:
                    raise ValueError(f"unknown modifier {mod!r}")
                actions.key_down(key)
                held.append(key)

        button_l = button.lower()
        if button_l == "right":
            actions.context_click(element)
        elif double:
            actions.double_click(element)
        elif button_l == "left":
            actions.click(element)
        else:
            raise ValueError(f"unsupported button {button!r}")

        for key in held:
            actions.key_up(key)
        actions.perform()
        return {"clicked": target}

    @capability("core")
    def browser_type(
        self,
        target: str,
        text: str,
        submit: bool = False,
        slowly: bool = False,
    ) -> dict[str, Any]:
        """Send ``text`` to the element matched by ``target``.

        Does not clear the field first (matching Playwright semantics).
        ``slowly=True`` sends one character at a time with a small delay
        between keys; ``submit=True`` follows the input with ``ENTER``.
        """

        element = self._find(target)
        if slowly:
            for char in text:
                element.send_keys(char)
                time.sleep(0.03)
        else:
            element.send_keys(text)
        if submit:
            element.send_keys(Keys.ENTER)
        return {"typed": text[:80], "submit": submit}

    @capability("core")
    def browser_fill_form(self, fields: list[dict[str, Any]]) -> dict[str, Any]:
        """Fill multiple form fields in one call.

        Each field is ``{"selector": str, "value": str | bool}``. Text
        inputs receive ``send_keys``; checkbox/radio inputs are clicked
        only when their current state does not match the desired boolean;
        ``<select>`` elements use Selenium's :class:`Select` helper, trying
        ``select_by_value`` before ``select_by_visible_text``. Returns the
        list of selectors that were filled plus any that were skipped with
        a reason.
        """

        self._require_driver()
        filled: list[str] = []
        skipped: list[dict[str, str]] = []

        for entry in fields:
            selector = entry.get("selector")
            value = entry.get("value")
            if not selector:
                skipped.append({"selector": str(selector), "reason": "no selector"})
                continue
            try:
                element = self._find(selector)
            except NoSuchElementException as exc:
                skipped.append({"selector": selector, "reason": str(exc)})
                continue

            tag = (element.tag_name or "").lower()
            input_type = (element.get_attribute("type") or "").lower()

            if tag == "select":
                select = Select(element)
                try:
                    select.select_by_value(str(value))
                except Exception:
                    try:
                        select.select_by_visible_text(str(value))
                    except Exception as exc:
                        skipped.append({"selector": selector, "reason": str(exc)})
                        continue
                filled.append(selector)
                continue

            if tag == "input" and input_type in ("checkbox", "radio"):
                want = bool(value)
                is_checked = element.is_selected()
                if want != is_checked:
                    element.click()
                filled.append(selector)
                continue

            element.send_keys(str(value))
            filled.append(selector)

        return {"filled": filled, "skipped": skipped}

    @capability("core")
    def browser_press_key(self, key: str) -> dict[str, Any]:
        """Press a key against the active element.

        ``key`` is either a single character (sent as-is) or the name of a
        :class:`selenium.webdriver.common.keys.Keys` constant (e.g.
        ``"ENTER"``, ``"ESCAPE"``, ``"F5"``). Lookups are case-insensitive.
        """

        drv = self._require_driver()
        upper = key.upper()
        mapped = getattr(Keys, upper, None)
        to_send = mapped if isinstance(mapped, str) else key
        ActionChains(drv).send_keys(to_send).perform()
        return {"pressed": key}

    @capability("core")
    def browser_hover(self, target: str) -> dict[str, Any]:
        """Move the cursor over the first element matching ``target``."""

        drv = self._require_driver()
        element = self._find(target)
        ActionChains(drv).move_to_element(element).perform()
        return {"hovered": target}

    @capability("core")
    def browser_select_option(
        self, target: str, values: list[str]
    ) -> dict[str, Any]:
        """Select one or more options on a ``<select>`` element.

        For each entry in ``values`` the helper tries ``select_by_value``
        first and falls back to ``select_by_visible_text``. Returns the
        list of values that were applied (entries that matched neither key
        are omitted).
        """

        element = self._find(target)
        select = Select(element)
        applied: list[str] = []
        for value in values:
            try:
                select.select_by_value(value)
                applied.append(value)
                continue
            except Exception:
                pass
            try:
                select.select_by_visible_text(value)
                applied.append(value)
            except Exception:
                continue
        return {"selected": applied}

    @capability("core")
    def browser_drag(self, start: str, end: str) -> dict[str, Any]:
        """Drag from the element at ``start`` to the element at ``end``."""

        drv = self._require_driver()
        src = self._find(start)
        dst = self._find(end)
        ActionChains(drv).drag_and_drop(src, dst).perform()
        return {"dragged": [start, end]}

    @capability("core")
    def browser_scroll(
        self, delta_x: int = 0, delta_y: int = 0
    ) -> dict[str, Any]:
        """Scroll the page by ``(delta_x, delta_y)`` pixels and report the
        new ``window.scrollX``/``scrollY``.
        """

        drv = self._require_driver()
        drv.execute_script(
            "window.scrollBy(arguments[0], arguments[1]);", int(delta_x), int(delta_y)
        )
        position = drv.execute_script(
            "return {x: window.scrollX, y: window.scrollY};"
        )
        return {"scrollX": position["x"], "scrollY": position["y"]}

    @capability("core")
    def browser_handle_dialog(
        self, accept: bool, prompt_text: str | None = None
    ) -> dict[str, Any]:
        """Accept or dismiss the currently-open JavaScript dialog.

        Provide ``prompt_text`` to fill a ``window.prompt`` before acting.
        Raises :class:`TorBrowserDriverError` when no dialog is open.
        """

        drv = self._require_driver()
        try:
            alert = drv.switch_to.alert
            text = alert.text
        except NoAlertPresentException as exc:
            raise TorBrowserDriverError("no dialog present") from exc

        if prompt_text is not None:
            alert.send_keys(prompt_text)
        if accept:
            alert.accept()
            action = "accept"
        else:
            alert.dismiss()
            action = "dismiss"
        return {"text": text, "action": action}

    @capability("core")
    def browser_file_upload(
        self, target: str, paths: list[str]
    ) -> dict[str, Any]:
        """Send local file paths to a ``<input type=file>`` element.

        Each path is validated through
        :meth:`PathPolicy.resolve_input` before being forwarded to
        ``send_keys``; rejected paths raise :class:`PathNotAllowed` and
        abort the call.
        """

        element = self._find(target)
        resolved = [
            str(self.config.path_policy.resolve_input(p)) for p in paths
        ]
        element.send_keys("\n".join(resolved))
        return {"uploaded": resolved}

    @capability("core")
    def browser_evaluate(
        self,
        script: str,
        selector: str | None = None,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Run ``script`` synchronously via ``execute_script``.

        The script is passed verbatim - include an explicit ``return ...``
        statement to surface a value. When ``selector`` is set, the matched
        element is forwarded as ``arguments[0]``. ``filename`` writes the
        JSON-encoded result to the output dir; otherwise the result is
        returned inline under ``result``.
        """

        drv = self._require_driver()
        if selector is not None:
            element = self._find(selector)
            result = drv.execute_script(script, element)
        else:
            result = drv.execute_script(script)

        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(result, ensure_ascii=False, default=str).encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data)}
        return {"result": result}

    @capability("core")
    def browser_evaluate_async(
        self,
        script: str,
        selector: str | None = None,
        timeout: float = 30.0,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Run ``script`` asynchronously via ``execute_async_script``.

        The script must invoke ``arguments[arguments.length - 1]`` as its
        completion callback. The driver's async-script timeout is set to
        ``timeout`` for the duration of the call. ``selector`` and
        ``filename`` behave as in :meth:`browser_evaluate`.
        """

        drv = self._require_driver()
        drv.set_script_timeout(float(timeout))
        try:
            if selector is not None:
                element = self._find(selector)
                result = drv.execute_async_script(script, element)
            else:
                result = drv.execute_async_script(script)
        finally:
            pass

        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(result, ensure_ascii=False, default=str).encode("utf-8")
            path.write_bytes(data)
            return {"path": str(path), "bytes": len(data)}
        return {"result": result}

    @capability("core")
    def browser_tabs(
        self,
        action: str,
        index: int | None = None,
        url: str | None = None,
    ) -> dict[str, Any]:
        """Manage tabs (``"list"``, ``"new"``, ``"select"``, ``"close"``).

        ``"new"`` opens a fresh tab via ``switch_to.new_window("tab")`` and
        optionally navigates it. ``"select"`` switches to the handle at
        ``index``. ``"close"`` closes the handle at ``index`` (or the
        current tab when ``index`` is ``None``) and switches focus to a
        remaining tab. The return shape is uniform: a ``tabs`` list of
        ``{index, handle, title, url}`` plus ``current`` (the index of the
        focused handle, or ``None`` when none remain).
        """

        drv = self._require_driver()

        if action == "new":
            drv.switch_to.new_window("tab")
            if url is not None:
                drv.get(url)
        elif action == "select":
            if index is None:
                raise ValueError("select requires index")
            drv.switch_to.window(drv.window_handles[index])
        elif action == "close":
            handles = drv.window_handles
            if index is None:
                drv.close()
            else:
                target_handle = handles[index]
                drv.switch_to.window(target_handle)
                drv.close()
            remaining = drv.window_handles
            if remaining:
                drv.switch_to.window(remaining[0])
        elif action != "list":
            raise ValueError(f"unknown tabs action {action!r}")

        handles = drv.window_handles
        current_handle = drv.current_window_handle if handles else None
        tabs: list[dict[str, Any]] = []
        for i, handle in enumerate(handles):
            drv.switch_to.window(handle)
            tabs.append(
                {
                    "index": i,
                    "handle": handle,
                    "title": drv.title,
                    "url": drv.current_url,
                }
            )
        if current_handle is not None and current_handle in handles:
            drv.switch_to.window(current_handle)
        current = handles.index(current_handle) if current_handle in handles else None
        return {"tabs": tabs, "current": current}

    @capability("core")
    def browser_frames(self) -> dict[str, Any]:
        """List ``<iframe>`` and ``<frame>`` elements on the current document."""

        drv = self._require_driver()
        elements = drv.find_elements(By.TAG_NAME, "iframe") + drv.find_elements(
            By.TAG_NAME, "frame"
        )
        frames: list[dict[str, Any]] = []
        for i, el in enumerate(elements):
            frames.append(
                {
                    "index": i,
                    "id": el.get_attribute("id"),
                    "name": el.get_attribute("name"),
                    "src": el.get_attribute("src"),
                }
            )
        return {"frames": frames}

    @capability("core")
    def browser_frame_select(
        self, selector: str | None = None, index: int | None = None
    ) -> dict[str, Any]:
        """Switch the WebDriver context into a frame, by selector or index."""

        if (selector is None) == (index is None):
            raise ValueError("browser_frame_select needs exactly one of selector or index")
        drv = self._require_driver()
        if selector is not None:
            element = self._find(selector)
            drv.switch_to.frame(element)
            return {"selected": selector}
        drv.switch_to.frame(int(index))  # type: ignore[arg-type]
        return {"selected": index}

    @capability("core")
    def browser_frame_parent(self) -> dict[str, Any]:
        """Switch back to the parent of the currently-selected frame."""

        drv = self._require_driver()
        drv.switch_to.parent_frame()
        return {}

    @capability("core")
    def browser_frame_default(self) -> dict[str, Any]:
        """Switch back to the top-level document."""

        drv = self._require_driver()
        drv.switch_to.default_content()
        return {}

    @capability("core")
    def browser_downloads_list(self) -> dict[str, Any]:
        """List files in the output directory that look like downloads.

        Skips Firefox in-progress markers (``*.part``). The output dir
        doubles as Firefox's download destination by way of
        :func:`_load_bearing_prefs`.
        """

        out_dir = self.config.path_policy.output_dir
        downloads: list[dict[str, Any]] = []
        if out_dir.is_dir():
            for entry in sorted(out_dir.iterdir()):
                if not entry.is_file() or entry.name.endswith(".part"):
                    continue
                stat = entry.stat()
                downloads.append(
                    {
                        "name": entry.name,
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                    }
                )
        return {"downloads": downloads}

    @capability("core")
    def browser_download_save(
        self, name: str, filename: str | None = None
    ) -> dict[str, Any]:
        """Move/rename a downloaded file to a path under the output dir.

        ``name`` is looked up in :attr:`PathPolicy.output_dir`. When
        ``filename`` is given the file is renamed (still inside the
        policy-validated tree); otherwise the original location is
        returned.
        """

        source = self.config.path_policy.resolve_output(name)
        if not source.is_file():
            raise FileNotFoundError(
                f"download {name!r} not found under {self.config.path_policy.output_dir}"
            )
        if filename is None:
            target = source
        else:
            target = self.config.path_policy.resolve_output(filename)
            if target != source:
                os.replace(source, target)
        size = target.stat().st_size
        return {"path": str(target), "bytes": size}

    @capability("core")
    def browser_output_read(self, filename: str) -> dict[str, Any]:
        """Read a file under the output dir.

        Decodes as UTF-8 up to a 256 KiB soft cap and returns the text in
        ``text``. Larger or non-UTF-8 files come back as base64 with
        ``truncated`` indicating whether the encoded payload was clipped.
        """

        path = self.config.path_policy.resolve_output(filename)
        data = path.read_bytes()
        size = len(data)
        if size <= _TEXT_READ_INLINE_CAP:
            try:
                return {
                    "path": str(path),
                    "bytes": size,
                    "text": data.decode("utf-8"),
                }
            except UnicodeDecodeError:
                pass
        clipped = data[:_TEXT_READ_INLINE_CAP]
        return {
            "path": str(path),
            "bytes": size,
            "base64": base64.b64encode(clipped).decode("ascii"),
            "truncated": size > len(clipped),
        }

    @capability("core")
    def browser_output_list(self) -> dict[str, Any]:
        """Recursively list every file under the output directory."""

        out_dir = self.config.path_policy.output_dir
        files: list[dict[str, Any]] = []
        if out_dir.is_dir():
            for entry in sorted(out_dir.rglob("*")):
                if not entry.is_file():
                    continue
                stat = entry.stat()
                files.append(
                    {
                        "name": entry.name,
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "rel": str(entry.relative_to(out_dir).as_posix()),
                    }
                )
        return {"output_dir": str(out_dir), "files": files}

    @capability("core")
    def browser_output_delete(self, filename: str) -> dict[str, Any]:
        """Delete a file under the output directory."""

        path = self.config.path_policy.resolve_output(filename)
        if path.exists():
            path.unlink()
        return {"deleted": str(path)}

    @capability("core")
    def browser_dump_page(self, prefix: str | None = None) -> dict[str, Any]:
        """Write a fixed set of debug artifacts for the current page.

        Always produces the same nine files under :attr:`PathPolicy.output_dir`:
        ``<prefix>-source.html``, ``<prefix>-text.txt``,
        ``<prefix>-snapshot.json``, ``<prefix>-screenshot.png``,
        ``<prefix>-cookies.json``, ``<prefix>-localstorage.json``,
        ``<prefix>-sessionstorage.json``, ``<prefix>-console.json``, and
        ``<prefix>-network.json``. Artifacts that cannot be captured (the
        most common case being the console log on Firefox/geckodriver)
        still get a file containing the underlying helper's fallback
        payload, so the artifact set is invariant. ``prefix`` defaults to
        ``dump-<ms-timestamp>`` when ``None``.
        """

        drv = self._require_driver()
        if prefix is None:
            prefix = f"dump-{int(time.time() * 1000)}"

        policy = self.config.path_policy

        source_path = policy.resolve_output(f"{prefix}-source.html")
        source_path.write_bytes((drv.page_source or "").encode("utf-8"))

        text_path = policy.resolve_output(f"{prefix}-text.txt")
        body_text = drv.execute_script(
            "return document.body ? document.body.innerText : '';"
        ) or ""
        text_path.write_bytes(str(body_text).encode("utf-8"))

        snapshot_tree = drv.execute_script(
            _SNAPSHOT_JS, None, 12, False
        )
        snapshot_path = policy.resolve_output(f"{prefix}-snapshot.json")
        snapshot_path.write_bytes(
            json.dumps(snapshot_tree, ensure_ascii=False).encode("utf-8")
        )

        screenshot_name = f"{prefix}-screenshot.png"
        self.browser_take_screenshot(full_page=True, filename=screenshot_name)
        screenshot_path = policy.resolve_output(screenshot_name)

        cookies_payload = {"cookies": list(drv.get_cookies() or [])}
        cookies_path = policy.resolve_output(f"{prefix}-cookies.json")
        cookies_path.write_bytes(
            json.dumps(cookies_payload, ensure_ascii=False).encode("utf-8")
        )

        local_keys = drv.execute_script(
            "return Object.keys(window.localStorage);"
        ) or []
        local_payload = {"keys": list(local_keys), "size": len(local_keys)}
        local_path = policy.resolve_output(f"{prefix}-localstorage.json")
        local_path.write_bytes(
            json.dumps(local_payload, ensure_ascii=False).encode("utf-8")
        )

        session_keys = drv.execute_script(
            "return Object.keys(window.sessionStorage);"
        ) or []
        session_payload = {
            "keys": list(session_keys),
            "size": len(session_keys),
        }
        session_path = policy.resolve_output(f"{prefix}-sessionstorage.json")
        session_path.write_bytes(
            json.dumps(session_payload, ensure_ascii=False).encode("utf-8")
        )

        console = self.browser_console_messages(all=True)  # type: ignore[attr-defined]
        console_path = policy.resolve_output(f"{prefix}-console.json")
        if "path" in console:
            console_for_file = {
                k: v for k, v in console.items() if k not in ("path", "bytes")
            }
        else:
            console_for_file = console
        console_path.write_bytes(
            json.dumps(console_for_file, ensure_ascii=False).encode("utf-8")
        )

        network = self.browser_network_requests()  # type: ignore[attr-defined]
        network_path = policy.resolve_output(f"{prefix}-network.json")
        if "path" in network:
            network_for_file = {
                k: v for k, v in network.items() if k not in ("path", "bytes")
            }
        else:
            network_for_file = network
        network_path.write_bytes(
            json.dumps(network_for_file, ensure_ascii=False).encode("utf-8")
        )

        return {
            "prefix": prefix,
            "artifacts": {
                "source": str(source_path),
                "text": str(text_path),
                "snapshot": str(snapshot_path),
                "screenshot": str(screenshot_path),
                "cookies": str(cookies_path),
                "localstorage": str(local_path),
                "sessionstorage": str(session_path),
                "console": str(console_path),
                "network": str(network_path),
            },
            "url": drv.current_url,
            "title": drv.title,
        }
