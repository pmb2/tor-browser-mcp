"""Page-inventory primitives implementing the ``extract`` capability.

Each method runs a single ``execute_script`` against the current document
and reshapes the result into a JSON-serialisable dict. The intent is to
give the higher MCP layer cheap, transport-safe summaries (links, forms,
inputs, scripts, metadata, tables, free-text and selector matches) without
needing to parse the page source on the Python side.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .capabilities import capability

if TYPE_CHECKING:
    from selenium import webdriver

    from .config import DriverConfig


_LINKS_JS = r"""
return Array.from(document.querySelectorAll('a[href]')).map(function (a) {
  return {
    href: a.href || a.getAttribute('href') || '',
    text: (a.textContent || '').trim(),
    title: a.getAttribute('title'),
    rel: a.getAttribute('rel'),
  };
});
"""

_FORMS_JS = r"""
return Array.from(document.querySelectorAll('form')).map(function (form) {
  var fields = Array.from(form.querySelectorAll('input, select, textarea')).map(
    function (el) {
      return {
        name: el.getAttribute('name'),
        type: (el.getAttribute('type') || el.tagName || '').toLowerCase(),
        id: el.getAttribute('id'),
        value: el.value == null ? null : String(el.value),
      };
    }
  );
  return {
    action: form.getAttribute('action'),
    method: (form.getAttribute('method') || 'get').toLowerCase(),
    id: form.getAttribute('id'),
    name: form.getAttribute('name'),
    fields: fields,
  };
});
"""

_INPUTS_JS = r"""
return Array.from(document.querySelectorAll('input, textarea, select')).map(
  function (el) {
    return {
      tag: (el.tagName || '').toLowerCase(),
      type: (el.getAttribute('type') || el.tagName || '').toLowerCase(),
      name: el.getAttribute('name'),
      id: el.getAttribute('id'),
      value: el.value == null ? null : String(el.value),
      placeholder: el.getAttribute('placeholder'),
    };
  }
);
"""

_SCRIPTS_JS = r"""
var includeInline = !!arguments[0];
return Array.from(document.querySelectorAll('script')).map(function (s) {
  var src = s.getAttribute('src');
  var inline = !src;
  var text = inline ? (s.textContent || '') : '';
  return {
    src: src,
    inline: inline,
    length: inline ? text.length : 0,
    preview: includeInline && inline ? text.slice(0, 200) : null,
  };
});
"""

_METADATA_JS = r"""
var html = document.documentElement;
var canonicalEl = document.querySelector("link[rel='canonical']");
var meta = Array.from(document.querySelectorAll('meta')).map(function (m) {
  return {
    name: m.getAttribute('name'),
    property: m.getAttribute('property'),
    content: m.getAttribute('content'),
  };
});
return {
  title: document.title || null,
  lang: html ? html.getAttribute('lang') : null,
  charset: document.characterSet || null,
  canonical: canonicalEl ? canonicalEl.getAttribute('href') : null,
  meta: meta,
};
"""

_TABLES_JS = r"""
var rowCap = arguments[0] | 0;
return Array.from(document.querySelectorAll('table')).map(function (table) {
  var headers = Array.from(table.querySelectorAll('thead th')).map(function (h) {
    return (h.textContent || '').trim();
  });
  if (headers.length === 0) {
    var firstRow = table.querySelector('tr');
    if (firstRow) {
      headers = Array.from(firstRow.querySelectorAll('th')).map(function (h) {
        return (h.textContent || '').trim();
      });
    }
  }
  var bodyRows = Array.from(table.querySelectorAll('tbody tr'));
  if (bodyRows.length === 0) {
    bodyRows = Array.from(table.querySelectorAll('tr')).filter(function (tr) {
      return tr.querySelector('td');
    });
  }
  var truncated = false;
  if (bodyRows.length > rowCap) {
    bodyRows = bodyRows.slice(0, rowCap);
    truncated = true;
  }
  var rows = bodyRows.map(function (tr) {
    return Array.from(tr.querySelectorAll('td, th')).map(function (cell) {
      return (cell.textContent || '').trim();
    });
  });
  var colcount = headers.length;
  rows.forEach(function (r) { if (r.length > colcount) colcount = r.length; });
  return {
    headers: headers,
    rows: rows,
    rowcount: rows.length,
    colcount: colcount,
    truncated: truncated,
  };
});
"""

_BODY_TEXT_JS = "return document.body ? document.body.innerText : '';"

_SELECTOR_PROBE_JS = r"""
var sel = arguments[0];
var nodes = document.querySelectorAll(sel);
if (nodes.length === 0) {
  return { count: 0, first: null };
}
var first = nodes[0];
return {
  count: nodes.length,
  first: {
    tag: (first.tagName || '').toLowerCase(),
    text: (first.textContent || '').trim().slice(0, 200),
    id: first.getAttribute('id'),
    class: first.getAttribute('class'),
  },
};
"""


_TABLE_ROW_CAP = 200
_SNIPPET_HALF = 40


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - _SNIPPET_HALF)
    right = min(len(text), end + _SNIPPET_HALF)
    return text[left:right]


class _ExtractCapabilityMixin:
    """Implements the ``extract`` capability surface on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: "webdriver.Firefox | None"
        config: "DriverConfig"

        def _require_driver(self) -> "webdriver.Firefox": ...

    @capability("extract")
    def browser_extract_links(self, url_filter: str | None = None) -> dict[str, Any]:
        """Return every ``<a href>`` on the page.

        ``url_filter`` is an optional case-insensitive substring matched
        against the ``href``. Each entry carries ``href``, ``text``,
        ``title``, and ``rel``.
        """

        drv = self._require_driver()
        links = list(drv.execute_script(_LINKS_JS) or [])
        if url_filter is not None:
            needle = url_filter.lower()
            links = [
                link
                for link in links
                if needle in str(link.get("href") or "").lower()
            ]
        return {"links": links}

    @capability("extract")
    def browser_extract_forms(self) -> dict[str, Any]:
        """Return every ``<form>`` with its action/method and child fields."""

        drv = self._require_driver()
        forms = list(drv.execute_script(_FORMS_JS) or [])
        return {"forms": forms}

    @capability("extract")
    def browser_extract_inputs(self) -> dict[str, Any]:
        """Return every ``<input>``, ``<textarea>``, and ``<select>`` on the page."""

        drv = self._require_driver()
        inputs = list(drv.execute_script(_INPUTS_JS) or [])
        return {"inputs": inputs}

    @capability("extract")
    def browser_extract_scripts(
        self, include_inline: bool = False
    ) -> dict[str, Any]:
        """Return every ``<script>`` element.

        ``src`` is the external URL (or ``None`` for inline scripts).
        ``length`` is the character count of inline content.
        ``preview`` carries the first ~200 characters of inline content
        only when ``include_inline=True``.
        """

        drv = self._require_driver()
        scripts = list(
            drv.execute_script(_SCRIPTS_JS, bool(include_inline)) or []
        )
        return {"scripts": scripts}

    @capability("extract")
    def browser_extract_metadata(self) -> dict[str, Any]:
        """Return ``<meta>`` tags plus title, language, charset, and canonical."""

        drv = self._require_driver()
        result = drv.execute_script(_METADATA_JS) or {}
        result.setdefault("meta", [])
        return result

    @capability("extract")
    def browser_extract_tables(self) -> dict[str, Any]:
        """Return one entry per ``<table>`` with headers and cell rows.

        Each table is capped at 200 rows; tables that exceed the cap carry
        ``truncated: true``. ``colcount`` is the maximum row length
        observed (or the header count, whichever is larger).
        """

        drv = self._require_driver()
        tables = list(drv.execute_script(_TABLES_JS, _TABLE_ROW_CAP) or [])
        return {"tables": tables}

    @capability("extract")
    def browser_find_text(
        self, pattern: str, regex: bool = False
    ) -> dict[str, Any]:
        """Search ``document.body.innerText`` for ``pattern``.

        With ``regex=False`` a case-sensitive substring scan is run. With
        ``regex=True`` ``pattern`` is compiled as a Python regular
        expression. Each match is returned with its ``offset`` into the body
        text and an ~80-character ``snippet`` centred on the match.
        """

        drv = self._require_driver()
        body = drv.execute_script(_BODY_TEXT_JS) or ""

        matches: list[dict[str, Any]] = []
        if regex:
            compiled = re.compile(pattern)
            for m in compiled.finditer(body):
                matches.append(
                    {"offset": m.start(), "snippet": _snippet(body, m.start(), m.end())}
                )
        else:
            start = 0
            needle_len = len(pattern)
            if needle_len == 0:
                return {"pattern": pattern, "regex": regex, "matches": []}
            while True:
                idx = body.find(pattern, start)
                if idx < 0:
                    break
                matches.append(
                    {
                        "offset": idx,
                        "snippet": _snippet(body, idx, idx + needle_len),
                    }
                )
                start = idx + needle_len

        return {"pattern": pattern, "regex": regex, "matches": matches}

    @capability("extract")
    def browser_find_selector(self, selector: str) -> dict[str, Any]:
        """Return the match count for ``selector`` plus a summary of the first hit."""

        drv = self._require_driver()
        result = drv.execute_script(_SELECTOR_PROBE_JS, selector) or {
            "count": 0,
            "first": None,
        }
        return {
            "selector": selector,
            "count": int(result.get("count") or 0),
            "first": result.get("first"),
        }
