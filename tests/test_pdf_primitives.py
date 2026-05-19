"""Tests for the ``pdf`` capability driver primitives."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from torbrowser_driver import PathPolicy, TorBrowserDriver, TorBrowserDriverError


_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\nfake-content"
_PDF_B64 = base64.b64encode(_PDF_BYTES).decode("ascii")


def test_browser_pdf_save_writes_decoded_bytes(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.print_page.return_value = _PDF_B64

    result = drv.browser_pdf_save(filename="doc.pdf")

    assert result["bytes"] == len(_PDF_BYTES)
    written = Path(result["path"])
    assert written.exists()
    assert written.read_bytes() == _PDF_BYTES
    assert written.parent == policy.output_dir


def test_browser_pdf_save_default_filename_is_timestamped(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.print_page.return_value = _PDF_B64

    result = drv.browser_pdf_save()

    written = Path(result["path"])
    assert written.parent == policy.output_dir
    assert written.name.startswith("page-")
    assert written.name.endswith(".pdf")
    # millisecond-style timestamp produces a long numeric stem
    stem = written.stem[len("page-") :]
    assert stem.isdigit()
    assert len(stem) >= 10


def test_browser_pdf_save_landscape_sets_orientation(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    import torbrowser_driver._pdf_primitives as pdf_mod

    seen: dict[str, object] = {}

    class _Recorder:
        def __init__(self) -> None:
            self.orientation: str | None = None
            self.background: bool | None = None
            self.scale: float | None = None
            self.page_ranges: list[str] | None = None

        def __setattr__(self, key: str, value: object) -> None:
            object.__setattr__(self, key, value)
            seen[key] = value

    monkeypatch.setattr(pdf_mod, "PrintOptions", _Recorder)
    drv.webdriver.print_page.return_value = _PDF_B64

    drv.browser_pdf_save(landscape=True)

    assert seen["orientation"] == "landscape"


def test_browser_pdf_save_print_background_and_scale(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    import torbrowser_driver._pdf_primitives as pdf_mod

    captured: dict[str, object] = {}

    class _Recorder:
        def __setattr__(self, key: str, value: object) -> None:
            object.__setattr__(self, key, value)
            captured[key] = value

    monkeypatch.setattr(pdf_mod, "PrintOptions", _Recorder)
    drv.webdriver.print_page.return_value = _PDF_B64

    drv.browser_pdf_save(print_background=False, scale=0.75)
    assert captured["background"] is False
    assert captured["scale"] == pytest.approx(0.75)


def test_browser_pdf_save_page_ranges_pass_through(
    monkeypatch, drv: TorBrowserDriver
) -> None:
    import torbrowser_driver._pdf_primitives as pdf_mod

    captured: dict[str, object] = {}

    class _Recorder:
        def __setattr__(self, key: str, value: object) -> None:
            object.__setattr__(self, key, value)
            captured[key] = value

    monkeypatch.setattr(pdf_mod, "PrintOptions", _Recorder)
    drv.webdriver.print_page.return_value = _PDF_B64

    drv.browser_pdf_save(page_ranges=["1-3", "7"])
    assert captured["page_ranges"] == ["1-3", "7"]


def test_browser_pdf_save_scale_out_of_range_raises(
    drv: TorBrowserDriver,
) -> None:
    with pytest.raises(ValueError, match="scale"):
        drv.browser_pdf_save(scale=2.5)
    with pytest.raises(ValueError, match="scale"):
        drv.browser_pdf_save(scale=0.0)


def test_browser_pdf_save_empty_payload_raises(drv: TorBrowserDriver) -> None:
    drv.webdriver.print_page.return_value = ""
    with pytest.raises(TorBrowserDriverError, match="no data"):
        drv.browser_pdf_save()


def test_browser_pdf_save_rejects_empty_page_ranges_list(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.print_page.return_value = _PDF_B64
    with pytest.raises(ValueError, match="page_ranges"):
        drv.browser_pdf_save(page_ranges=[])
    with pytest.raises(ValueError, match="page_ranges"):
        drv.browser_pdf_save(page_ranges=["  "])
