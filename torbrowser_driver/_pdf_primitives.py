"""PDF-export primitive implementing the ``pdf`` capability.

Backed by Selenium's :meth:`WebDriver.print_page`, which round-trips
through Marionette's printing API to render the current document as a
PDF. The returned payload is base64; this layer decodes it and writes the
bytes under :class:`PathPolicy.output_dir`.

The capability is opt-in because Firefox's headless print pipeline has
historically been fragile in Tor Browser builds; if ``print_page`` ever
stops returning usable bytes against the bundled ESR, this module should
degrade to :class:`NotImplementedError` rather than ship a broken tool.
"""

from __future__ import annotations

import base64
import binascii
import time
from typing import TYPE_CHECKING, Any

from selenium.webdriver.common.print_page_options import PrintOptions

from .capabilities import capability

if TYPE_CHECKING:
    from selenium import webdriver

    from .config import DriverConfig


_MIN_SCALE = 0.1
_MAX_SCALE = 2.0


def _validate_page_ranges(page_ranges: list[str]) -> list[str]:
    if not isinstance(page_ranges, list) or not page_ranges:
        raise ValueError(
            "page_ranges must be a non-empty list of strings like '1-3' or '5'"
        )
    validated: list[str] = []
    for entry in page_ranges:
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError(
                f"page_ranges entries must be non-empty strings; got {entry!r}"
            )
        validated.append(entry.strip())
    return validated


class _PdfCapabilityMixin:
    """Implements the ``pdf`` capability surface on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: "webdriver.Firefox | None"
        config: "DriverConfig"

        def _require_driver(self) -> "webdriver.Firefox": ...

    @capability("pdf")
    def browser_pdf_save(
        self,
        filename: str | None = None,
        landscape: bool = False,
        print_background: bool = True,
        scale: float = 1.0,
        page_ranges: list[str] | None = None,
    ) -> dict[str, Any]:
        """Render the current document to a PDF written under the output dir.

        Wraps :meth:`selenium.webdriver.Firefox.print_page`, which returns
        base64-encoded PDF bytes; the bytes are decoded and written to
        ``filename`` (or a timestamped ``page-<ms>.pdf`` when ``filename``
        is ``None``). ``landscape`` flips ``PrintOptions.orientation``;
        ``print_background`` controls whether CSS backgrounds render;
        ``scale`` is forwarded verbatim and must lie within ``[0.1, 2.0]``,
        the range Firefox accepts. ``page_ranges`` accepts strings like
        ``"1-3"`` or ``"5"``; the entries are surface-validated only -
        malformed ranges surface as Firefox-side errors.

        If ``print_page`` fails or returns no data, the exception is
        re-raised so callers can detect Tor-Browser print-pipeline
        breakage and react (rather than receiving an empty PDF on disk).
        """

        if not (_MIN_SCALE <= float(scale) <= _MAX_SCALE):
            raise ValueError(
                f"scale {scale!r} is outside the supported range "
                f"[{_MIN_SCALE}, {_MAX_SCALE}]"
            )

        drv = self._require_driver()

        options = PrintOptions()
        options.orientation = "landscape" if landscape else "portrait"
        options.background = bool(print_background)
        options.scale = float(scale)
        if page_ranges is not None:
            options.page_ranges = _validate_page_ranges(page_ranges)

        encoded = drv.print_page(options)
        if not encoded:
            raise RuntimeError(
                "WebDriver.print_page returned no data; the Tor Browser "
                "build may not expose a working print pipeline"
            )

        try:
            pdf_bytes = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError(
                f"WebDriver.print_page returned non-base64 data: {exc}"
            ) from exc

        out_name = filename or f"page-{int(time.time() * 1000)}.pdf"
        path = self.config.path_policy.resolve_output(out_name)
        path.write_bytes(pdf_bytes)
        return {"path": str(path), "bytes": len(pdf_bytes)}
