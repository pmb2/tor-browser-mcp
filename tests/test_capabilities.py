"""Tests for the capability registry."""

from __future__ import annotations

import pytest

from torbrowser_driver import (
    DEFAULT_CAPABILITIES,
    DriverConfigError,
    KNOWN_CAPABILITIES,
    OPTIONAL_CAPABILITIES,
    TorBrowserDriver,
    capability,
    registered_methods,
)


EXPECTED_CORE_METHODS: frozenset[str] = frozenset(
    {
        "browser_navigate",
        "browser_navigate_back",
        "browser_navigate_forward",
        "browser_reload",
        "browser_close",
        "browser_current_url",
        "browser_title",
        "browser_page_source",
        "browser_snapshot",
        "browser_take_screenshot",
        "browser_wait_for",
        "browser_click",
        "browser_type",
        "browser_fill_form",
        "browser_press_key",
        "browser_hover",
        "browser_select_option",
        "browser_drag",
        "browser_scroll",
        "browser_handle_dialog",
        "browser_file_upload",
        "browser_evaluate",
        "browser_evaluate_async",
        "browser_tabs",
        "browser_frames",
        "browser_frame_select",
        "browser_frame_parent",
        "browser_frame_default",
        "browser_downloads_list",
        "browser_download_save",
        "browser_output_read",
        "browser_output_list",
        "browser_output_delete",
    }
)


def test_known_is_union_of_default_and_optional() -> None:
    assert KNOWN_CAPABILITIES == DEFAULT_CAPABILITIES | OPTIONAL_CAPABILITIES
    assert DEFAULT_CAPABILITIES.isdisjoint(OPTIONAL_CAPABILITIES)


def test_decorator_attaches_metadata() -> None:
    @capability("core")
    def f() -> None:
        return None

    assert f._capability == "core"  # type: ignore[attr-defined]
    assert not hasattr(f, "_tool_name")


def test_decorator_tool_name_override() -> None:
    @capability("core", tool_name="renamed")
    def g() -> None:
        return None

    assert g._capability == "core"  # type: ignore[attr-defined]
    assert g._tool_name == "renamed"  # type: ignore[attr-defined]


def test_unknown_capability_raises() -> None:
    with pytest.raises(DriverConfigError):

        @capability("bogus")
        def h() -> None:
            return None


def test_registered_methods_core_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"core"})
    assert set(methods.keys()) == EXPECTED_CORE_METHODS


def test_registered_methods_empty_caps_returns_empty() -> None:
    assert registered_methods(TorBrowserDriver, frozenset()) == {}


def test_registered_methods_respects_tool_name() -> None:
    class Toy:
        @capability("core", tool_name="aliased_tool")
        def real_name(self) -> None:
            return None

    methods = registered_methods(Toy, {"core"})
    assert "aliased_tool" in methods
    assert "real_name" not in methods
