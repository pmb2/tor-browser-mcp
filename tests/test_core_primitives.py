"""Tests for the ``core`` capability driver primitives.

These tests construct a :class:`TorBrowserDriver` without entering the
context manager: ``__new__`` is used to skip the real launch, and the
``webdriver`` attribute is replaced with a :class:`unittest.mock.MagicMock`.
The goal is to exercise the method bodies (argument validation, path
policy interaction, return shape, JS-glue wrapping) without booting a
browser.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

import pytest

from torbrowser_driver import (
    BrowserTimeoutError,
    PathNotAllowed,
    PathPolicy,
    TorBrowserDriver,
    TorBrowserDriverError,
)

from tests.conftest import _FakeConfig


def test_require_driver_raises_when_not_started(policy: PathPolicy) -> None:
    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = _FakeConfig(path_policy=policy)  # type: ignore[assignment]
    instance.webdriver = None
    with pytest.raises(TorBrowserDriverError, match="context manager"):
        instance.browser_current_url()


def test_browser_navigate_returns_url_and_title(drv: TorBrowserDriver) -> None:
    drv.webdriver.current_url = "https://example.com/landed"
    drv.webdriver.title = "Example"
    result = drv.browser_navigate("https://example.com/")
    drv.webdriver.get.assert_called_once_with("https://example.com/")
    assert result == {"url": "https://example.com/landed", "title": "Example"}


def test_browser_navigate_rejects_disallowed_file_url(drv: TorBrowserDriver) -> None:
    with pytest.raises(PathNotAllowed):
        drv.browser_navigate("file:///etc/passwd")
    drv.webdriver.get.assert_not_called()


def test_browser_current_url_and_title(drv: TorBrowserDriver) -> None:
    drv.webdriver.current_url = "https://x/"
    drv.webdriver.title = "T"
    assert drv.browser_current_url() == {"url": "https://x/"}
    assert drv.browser_title() == {"title": "T"}


def test_browser_navigate_back_forward_reload(drv: TorBrowserDriver) -> None:
    drv.webdriver.current_url = "https://x/"
    assert drv.browser_navigate_back() == {"url": "https://x/"}
    drv.webdriver.back.assert_called_once()
    assert drv.browser_navigate_forward() == {"url": "https://x/"}
    drv.webdriver.forward.assert_called_once()
    assert drv.browser_reload() == {"url": "https://x/"}
    drv.webdriver.refresh.assert_called_once()


def test_browser_close_switches_to_remaining_tab(drv: TorBrowserDriver) -> None:
    drv.webdriver.current_window_handle = "h1"
    drv.webdriver.window_handles = ["h2"]
    result = drv.browser_close()
    drv.webdriver.close.assert_called_once()
    drv.webdriver.switch_to.window.assert_called_once_with("h2")
    assert result == {"closed": "h1", "remaining": ["h2"]}


def test_browser_page_source_inline(drv: TorBrowserDriver) -> None:
    drv.webdriver.page_source = "<html><body>hi</body></html>"
    result = drv.browser_page_source()
    assert result == {
        "source": "<html><body>hi</body></html>",
        "truncated": False,
    }


def test_browser_page_source_truncates_when_huge(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.page_source = "x" * (2 * 1024 * 1024)
    result = drv.browser_page_source()
    assert result["truncated"] is True
    assert len(result["source"]) <= 1_048_576


def test_browser_page_source_to_file(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.page_source = "<p>hi</p>"
    result = drv.browser_page_source(filename="page.html")
    expected = policy.output_dir / "page.html"
    assert Path(result["path"]) == expected.resolve()
    assert result["bytes"] == len(b"<p>hi</p>")
    assert expected.read_text(encoding="utf-8") == "<p>hi</p>"


def test_browser_take_screenshot_writes_default_filename(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    png_bytes = b"\x89PNG\r\n\x1a\nfake"
    drv.webdriver.get_screenshot_as_png.return_value = png_bytes
    if hasattr(drv.webdriver, "get_full_page_screenshot_as_png"):
        del drv.webdriver.get_full_page_screenshot_as_png

    result = drv.browser_take_screenshot()
    path = Path(result["path"])
    assert path.parent == policy.output_dir.resolve()
    assert path.name.startswith("screenshot-")
    assert path.suffix == ".png"
    assert path.read_bytes() == png_bytes
    assert result["bytes"] == len(png_bytes)


def test_browser_take_screenshot_with_selector(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    element = MagicMock()
    element.screenshot_as_png = b"selected-png"
    drv.webdriver.find_element.return_value = element
    result = drv.browser_take_screenshot(selector="#main", filename="shot.png")
    assert Path(result["path"]) == (policy.output_dir / "shot.png").resolve()
    assert result["bytes"] == len(b"selected-png")
    assert Path(result["path"]).read_bytes() == b"selected-png"


def test_browser_wait_for_time_s_sleeps(drv: TorBrowserDriver) -> None:
    result = drv.browser_wait_for(time_s=0.05)
    assert result["waited"] == "time_s"
    assert result["elapsed"] >= 0.05


def test_browser_wait_for_requires_exactly_one_mode(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError):
        drv.browser_wait_for()
    with pytest.raises(ValueError):
        drv.browser_wait_for(text="a", time_s=0.0)


def test_browser_wait_for_text_succeeds(drv: TorBrowserDriver) -> None:
    body = MagicMock()
    body.text = "all good here"
    drv.webdriver.find_elements.return_value = [body]
    result = drv.browser_wait_for(text="good", timeout=1.0)
    assert result["waited"] == "text"


def test_browser_wait_for_text_times_out(drv: TorBrowserDriver) -> None:
    body = MagicMock()
    body.text = "nothing matches"
    drv.webdriver.find_elements.return_value = [body]
    with pytest.raises(BrowserTimeoutError):
        drv.browser_wait_for(text="missing", timeout=0.3)


def test_browser_type_send_keys(drv: TorBrowserDriver) -> None:
    element = MagicMock()
    drv.webdriver.find_element.return_value = element
    result = drv.browser_type("input#q", "hello", submit=True)
    assert element.send_keys.call_args_list[0].args == ("hello",)
    assert element.send_keys.call_args_list[-1].args[0].endswith("\ue007")
    assert result == {"typed": "hello", "submit": True}


def test_browser_scroll_reports_position(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.side_effect = [None, {"x": 10, "y": 200}]
    result = drv.browser_scroll(delta_x=10, delta_y=200)
    assert result == {"scrollX": 10, "scrollY": 200}


def test_browser_handle_dialog_accept(drv: TorBrowserDriver) -> None:
    alert = MagicMock()
    alert.text = "are you sure?"
    type(drv.webdriver.switch_to).alert = PropertyMock(return_value=alert)
    result = drv.browser_handle_dialog(accept=True, prompt_text="yes")
    alert.send_keys.assert_called_once_with("yes")
    alert.accept.assert_called_once()
    assert result == {"text": "are you sure?", "action": "accept"}


def test_browser_evaluate_inline_result(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = 42
    result = drv.browser_evaluate("return 42;")
    drv.webdriver.execute_script.assert_called_once_with("return 42;")
    assert result == {"result": 42}


def test_browser_evaluate_to_file(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.execute_script.return_value = {"k": 1}
    result = drv.browser_evaluate("return {k:1}", filename="eval.json")
    written = Path(result["path"])
    assert written == (policy.output_dir / "eval.json").resolve()
    assert json.loads(written.read_text(encoding="utf-8")) == {"k": 1}


def test_browser_output_list_and_read_and_delete(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    target = policy.output_dir / "note.txt"
    target.write_text("hello world", encoding="utf-8")

    listed = drv.browser_output_list()
    names = {entry["name"] for entry in listed["files"]}
    assert "note.txt" in names

    read = drv.browser_output_read("note.txt")
    assert read["text"] == "hello world"
    assert read["bytes"] == len(b"hello world")

    deleted = drv.browser_output_delete("note.txt")
    assert deleted["deleted"] == str(target.resolve())
    assert not target.exists()


def test_browser_output_read_binary_falls_back_to_base64(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    target = policy.output_dir / "blob.bin"
    target.write_bytes(b"\xff\xfe\x00\x01garbage")
    result = drv.browser_output_read("blob.bin")
    assert "base64" in result
    assert "text" not in result


def test_browser_downloads_list_skips_part_files(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    (policy.output_dir / "done.bin").write_bytes(b"x")
    (policy.output_dir / "in-progress.part").write_bytes(b"y")
    result = drv.browser_downloads_list()
    names = {entry["name"] for entry in result["downloads"]}
    assert names == {"done.bin"}


def test_browser_download_save_renames(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    source = policy.output_dir / "raw.bin"
    source.write_bytes(b"123")
    result = drv.browser_download_save("raw.bin", filename="archive/keep.bin")
    expected = (policy.output_dir / "archive" / "keep.bin").resolve()
    assert Path(result["path"]) == expected
    assert expected.read_bytes() == b"123"
    assert not source.exists()


def test_browser_file_upload_validates_paths(
    drv: TorBrowserDriver, policy: PathPolicy, tmp_path: Path
) -> None:
    element = MagicMock()
    drv.webdriver.find_element.return_value = element
    inside = policy.output_dir / "upload.txt"
    inside.write_text("ok")
    result = drv.browser_file_upload("input[type=file]", [str(inside)])
    element.send_keys.assert_called_once()
    sent = element.send_keys.call_args.args[0]
    assert str(inside.resolve()) in sent
    assert result["uploaded"] == [str(inside.resolve())]


def test_browser_file_upload_rejects_outside_paths(
    drv: TorBrowserDriver, tmp_path: Path
) -> None:
    drv.webdriver.find_element.return_value = MagicMock()
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("nope")
    with pytest.raises(PathNotAllowed):
        drv.browser_file_upload("input[type=file]", [str(outside)])


def test_browser_handle_dialog_without_alert_raises(drv: TorBrowserDriver) -> None:
    from selenium.common.exceptions import NoAlertPresentException

    type(drv.webdriver.switch_to).alert = PropertyMock(
        side_effect=NoAlertPresentException()
    )
    with pytest.raises(TorBrowserDriverError):
        drv.browser_handle_dialog(accept=True)


def test_browser_dump_page_writes_all_artifacts(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.page_source = "<html><body>hi</body></html>"
    drv.webdriver.current_url = "https://x.test/"
    drv.webdriver.title = "X"
    drv.webdriver.get_cookies.return_value = [{"name": "c", "value": "v"}]
    drv.webdriver.get_screenshot_as_png.return_value = b"\x89PNG\r\n\x1a\n"
    if hasattr(drv.webdriver, "get_full_page_screenshot_as_png"):
        del drv.webdriver.get_full_page_screenshot_as_png
    drv.webdriver.get_log.side_effect = RuntimeError("not supported")
    drv.webdriver.execute_script.side_effect = [
        "body text",                                     # innerText for dump
        {"tag": "html", "role": None, "name": None, "text": None, "children": [], "bounds": None},  # snapshot
        ["local-a"],                                     # localStorage keys
        [],                                              # sessionStorage keys
        [{"url": "https://x.test/", "initiator_type": "navigation"}],  # network entries
    ]

    result = drv.browser_dump_page(prefix="dump-test")
    artifacts = result["artifacts"]
    for path in artifacts.values():
        assert Path(path).is_file()
    assert result["url"] == "https://x.test/"
    assert result["title"] == "X"
    assert Path(artifacts["source"]).read_text(encoding="utf-8") == "<html><body>hi</body></html>"
    assert Path(artifacts["text"]).read_text(encoding="utf-8") == "body text"
    console_payload = json.loads(Path(artifacts["console"]).read_text(encoding="utf-8"))
    assert console_payload["supported"] is False
