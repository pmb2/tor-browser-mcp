"""Tests for the ``extract`` capability driver primitives."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from torbrowser_driver import PathPolicy, TorBrowserDriver


class _FakeConfig(SimpleNamespace):
    pass


@pytest.fixture()
def policy(tmp_path: Path) -> PathPolicy:
    out = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    return PathPolicy.from_config(output_dir=out, cwd=work)


@pytest.fixture()
def drv(policy: PathPolicy) -> TorBrowserDriver:
    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = _FakeConfig(path_policy=policy)  # type: ignore[assignment]
    instance.webdriver = MagicMock(name="webdriver")
    instance.controller = None
    instance._closed = False
    instance._tor_process = None
    instance._session_dir = None
    instance._owns_session_dir = False
    instance._owns_tor_data_dir = False
    return instance


def test_extract_links_filters_substring(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = [
        {"href": "https://x.test/a", "text": "A", "title": None, "rel": None},
        {"href": "https://x.test/b", "text": "B", "title": None, "rel": None},
        {"href": "https://y.test/", "text": "Y", "title": None, "rel": None},
    ]
    result = drv.browser_extract_links(filter="x.TEST")
    hrefs = [link["href"] for link in result["links"]]
    assert hrefs == ["https://x.test/a", "https://x.test/b"]


def test_extract_forms_passthrough(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = [
        {
            "action": "/submit",
            "method": "post",
            "id": "f1",
            "name": None,
            "fields": [
                {"name": "q", "type": "text", "id": "q", "value": ""},
            ],
        }
    ]
    result = drv.browser_extract_forms()
    assert result["forms"][0]["action"] == "/submit"
    assert result["forms"][0]["fields"][0]["name"] == "q"


def test_extract_inputs_passthrough(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = [
        {
            "tag": "input",
            "type": "text",
            "name": "q",
            "id": "q",
            "value": "",
            "placeholder": "search",
        }
    ]
    result = drv.browser_extract_inputs()
    assert result["inputs"][0]["placeholder"] == "search"


def test_extract_scripts_forwards_include_inline(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = [
        {"src": None, "inline": True, "length": 5, "preview": "alert"}
    ]
    drv.browser_extract_scripts(include_inline=True)
    args = drv.webdriver.execute_script.call_args.args
    assert args[1] is True


def test_extract_metadata_returns_shape(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = {
        "title": "T",
        "lang": "en",
        "charset": "UTF-8",
        "canonical": "https://x.test/",
        "meta": [{"name": "description", "property": None, "content": "d"}],
    }
    result = drv.browser_extract_metadata()
    assert result["title"] == "T"
    assert result["meta"][0]["content"] == "d"


def test_extract_tables_passthrough(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = [
        {
            "headers": ["a", "b"],
            "rows": [["1", "2"]],
            "rowcount": 1,
            "colcount": 2,
            "truncated": False,
        }
    ]
    result = drv.browser_extract_tables()
    assert result["tables"][0]["headers"] == ["a", "b"]


def test_find_text_substring(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = "the quick brown fox jumps over the lazy dog"
    result = drv.browser_find_text("the")
    offsets = [m["offset"] for m in result["matches"]]
    assert offsets == [0, 31]
    assert result["regex"] is False
    assert "the" in result["matches"][0]["snippet"]


def test_find_text_regex(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = "abc123 def456"
    result = drv.browser_find_text(r"\d+", regex=True)
    offsets = [m["offset"] for m in result["matches"]]
    assert offsets == [3, 10]
    assert result["regex"] is True


def test_find_text_empty_pattern(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = "abc"
    result = drv.browser_find_text("")
    assert result["matches"] == []


def test_find_selector_zero(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = {"count": 0, "first": None}
    result = drv.browser_find_selector("#none")
    assert result == {"selector": "#none", "count": 0, "first": None}


def test_find_selector_match(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.return_value = {
        "count": 3,
        "first": {"tag": "a", "text": "x", "id": None, "class": "link"},
    }
    result = drv.browser_find_selector("a.link")
    assert result["count"] == 3
    assert result["first"]["tag"] == "a"
