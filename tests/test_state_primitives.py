"""Tests for the ``state`` capability driver primitives."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from torbrowser_driver import PathPolicy, TorBrowserDriver


def test_cookie_list_filters_by_domain_and_path(drv: TorBrowserDriver) -> None:
    drv.webdriver.get_cookies.return_value = [
        {"name": "a", "domain": "x.test", "path": "/"},
        {"name": "b", "domain": "y.test", "path": "/"},
        {"name": "c", "domain": "x.test", "path": "/admin"},
    ]
    result = drv.browser_cookie_list(domain="x.test", path="/")
    assert [c["name"] for c in result["cookies"]] == ["a"]
    assert result["count"] == 1
    assert result["total"] == 1
    assert result["truncated"] is False


def test_cookie_list_limit_and_file_output(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.get_cookies.return_value = [
        {"name": "a", "domain": "x.test", "path": "/"},
        {"name": "b", "domain": "x.test", "path": "/"},
    ]
    limited = drv.browser_cookie_list(limit=1)
    assert [c["name"] for c in limited["cookies"]] == ["a"]
    assert limited["count"] == 1
    assert limited["total"] == 2
    assert limited["truncated"] is True

    written = drv.browser_cookie_list(filename="cookies.json")
    path = Path(written["path"])
    assert path == (policy.output_dir / "cookies.json").resolve()
    assert "cookies" not in written
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert [c["name"] for c in payload["cookies"]] == ["a", "b"]


def test_cookie_get_returns_cookie(drv: TorBrowserDriver) -> None:
    drv.webdriver.get_cookie.return_value = {"name": "a", "value": "1"}
    assert drv.browser_cookie_get("a") == {"cookie": {"name": "a", "value": "1"}}


def test_cookie_set_omits_domain_when_none(drv: TorBrowserDriver) -> None:
    drv.browser_cookie_set("a", "1", same_site="Lax", secure=True)
    drv.webdriver.add_cookie.assert_called_once()
    cookie = drv.webdriver.add_cookie.call_args.args[0]
    assert cookie["name"] == "a"
    assert cookie["value"] == "1"
    assert "domain" not in cookie
    assert cookie["sameSite"] == "Lax"
    assert cookie["secure"] is True


def test_cookie_set_rejects_bad_same_site(drv: TorBrowserDriver) -> None:
    with pytest.raises(ValueError):
        drv.browser_cookie_set("a", "1", same_site="bogus")


def test_cookie_delete_and_clear(drv: TorBrowserDriver) -> None:
    assert drv.browser_cookie_delete("a") == {"deleted": "a"}
    drv.webdriver.delete_cookie.assert_called_once_with("a")
    assert drv.browser_cookie_clear() == {"cleared": True}
    drv.webdriver.delete_all_cookies.assert_called_once()


def test_localstorage_roundtrip(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.side_effect = [
        ["a", "b"],
        "value-a",
        None,
        None,
        None,
        None,
    ]
    listed = drv.browser_localstorage_list()
    assert listed == {
        "keys": ["a", "b"],
        "size": 2,
        "count": 2,
        "total": 2,
        "truncated": False,
    }

    got = drv.browser_localstorage_get("a")
    assert got == {"key": "a", "value": "value-a"}

    assert drv.browser_localstorage_set("a", "value-a") == {"set": "a"}
    assert drv.browser_localstorage_delete("a") == {"deleted": "a"}
    assert drv.browser_localstorage_clear() == {"cleared": True}


def test_localstorage_list_limit_and_get_file_output(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.execute_script.side_effect = [["a", "b"], "value-a"]
    listed = drv.browser_localstorage_list(limit=1)
    assert listed["keys"] == ["a"]
    assert listed["size"] == 2
    assert listed["count"] == 1
    assert listed["truncated"] is True

    written = drv.browser_localstorage_get("a", filename="local-a.json")
    path = Path(written["path"])
    assert path == (policy.output_dir / "local-a.json").resolve()
    assert "value" not in written
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "key": "a",
        "value": "value-a",
    }


def test_sessionstorage_roundtrip(drv: TorBrowserDriver) -> None:
    drv.webdriver.execute_script.side_effect = [
        [],
        None,
        None,
        None,
        None,
    ]
    assert drv.browser_sessionstorage_list() == {
        "keys": [],
        "size": 0,
        "count": 0,
        "total": 0,
        "truncated": False,
    }
    assert drv.browser_sessionstorage_get("a") == {"key": "a", "value": None}
    assert drv.browser_sessionstorage_set("a", "v") == {"set": "a"}
    assert drv.browser_sessionstorage_delete("a") == {"deleted": "a"}
    assert drv.browser_sessionstorage_clear() == {"cleared": True}


def test_sessionstorage_list_file_output(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.execute_script.return_value = ["a", "b"]
    written = drv.browser_sessionstorage_list(limit=1, filename="session.json")
    path = Path(written["path"])
    assert path == (policy.output_dir / "session.json").resolve()
    assert "keys" not in written
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["keys"] == ["a"]
    assert payload["total"] == 2


def test_storage_state_writes_file(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.get_cookies.return_value = [
        {"name": "c", "value": "v", "domain": "x.test", "path": "/"}
    ]
    drv.webdriver.execute_script.side_effect = [
        "https://x.test",
        [{"name": "k1", "value": "v1"}],
        [{"name": "k2", "value": "v2"}],
    ]
    result = drv.browser_storage_state(filename="state.json")
    written = Path(result["path"])
    assert written == (policy.output_dir / "state.json").resolve()
    on_disk = json.loads(written.read_text(encoding="utf-8"))
    assert on_disk["cookies"][0]["name"] == "c"
    assert on_disk["origins"][0]["origin"] == "https://x.test"
    assert on_disk["origins"][0]["local_storage"] == [{"name": "k1", "value": "v1"}]
    assert on_disk["origins"][0]["session_storage"] == [
        {"name": "k2", "value": "v2"}
    ]


def test_storage_state_inline(drv: TorBrowserDriver) -> None:
    drv.webdriver.get_cookies.return_value = []
    drv.webdriver.execute_script.side_effect = ["https://x.test", [], []]
    result = drv.browser_storage_state()
    assert "storage_state" in result
    assert result["storage_state"]["origins"][0]["origin"] == "https://x.test"


def test_storage_state_large_inline_returns_summary(drv: TorBrowserDriver) -> None:
    drv.webdriver.get_cookies.return_value = []
    drv.webdriver.execute_script.side_effect = [
        "https://x.test",
        [{"name": "k", "value": "x" * 600_000}],
        [],
    ]
    result = drv.browser_storage_state()
    assert result["truncated"] is True
    assert result["bytes"] > result["inline_cap"]
    assert "storage_state" not in result


def test_set_storage_state_applies_current_origin_and_skips_others(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    state = {
        "cookies": [{"name": "c", "value": "v"}],
        "origins": [
            {
                "origin": "https://x.test",
                "local_storage": [{"name": "k1", "value": "v1"}],
                "session_storage": [{"name": "k2", "value": "v2"}],
            },
            {
                "origin": "https://other.test",
                "local_storage": [{"name": "ignored", "value": "y"}],
                "session_storage": [],
            },
        ],
    }
    path = policy.output_dir / "state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state), encoding="utf-8")

    drv.webdriver.execute_script.side_effect = [
        "https://x.test",  # current origin probe
        None,  # localStorage.setItem k1
        None,  # sessionStorage.setItem k2
    ]
    result = drv.browser_set_storage_state("state.json")
    drv.webdriver.add_cookie.assert_called_once_with({"name": "c", "value": "v"})
    assert result["applied"]["cookies"] == 1
    assert result["applied"]["origins"] == ["https://x.test"]
    assert len(result["applied"]["skipped"]) == 1
    assert result["applied"]["skipped"][0]["origin"] == "https://other.test"


def test_set_storage_state_reads_via_input_policy(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    state = {"cookies": [], "origins": []}
    path = policy.output_dir / "state.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    drv.webdriver.execute_script.return_value = "https://x.test"

    class _PolicySpy:
        output_dir = policy.output_dir

        def __init__(self) -> None:
            self.input_calls: list[str] = []

        def resolve_input(self, name: str | Path) -> Path:
            self.input_calls.append(str(name))
            return policy.resolve_input(name)

    spy = _PolicySpy()
    drv.config.path_policy = spy
    drv.browser_set_storage_state("state.json")

    assert spy.input_calls == [str(policy.output_dir / "state.json")]
