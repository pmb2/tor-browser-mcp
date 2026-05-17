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
        "browser_dump_page",
    }
)


EXPECTED_STATE_METHODS: frozenset[str] = frozenset(
    {
        "browser_cookie_list",
        "browser_cookie_get",
        "browser_cookie_set",
        "browser_cookie_delete",
        "browser_cookie_clear",
        "browser_localstorage_list",
        "browser_localstorage_get",
        "browser_localstorage_set",
        "browser_localstorage_delete",
        "browser_localstorage_clear",
        "browser_sessionstorage_list",
        "browser_sessionstorage_get",
        "browser_sessionstorage_set",
        "browser_sessionstorage_delete",
        "browser_sessionstorage_clear",
        "browser_storage_state",
        "browser_set_storage_state",
    }
)


EXPECTED_EXTRACT_METHODS: frozenset[str] = frozenset(
    {
        "browser_extract_links",
        "browser_extract_forms",
        "browser_extract_inputs",
        "browser_extract_scripts",
        "browser_extract_metadata",
        "browser_extract_tables",
        "browser_find_text",
        "browser_find_selector",
    }
)


EXPECTED_DIAGNOSTICS_METHODS: frozenset[str] = frozenset(
    {
        "browser_console_messages",
        "browser_get_config",
        "browser_fingerprint_probe",
    }
)


EXPECTED_TOR_METHODS: frozenset[str] = frozenset(
    {
        "tor_status",
        "tor_check_identity",
        "tor_new_identity",
        "tor_circuit_status",
        "tor_stream_status",
        "tor_entry_guards",
        "tor_get_info",
        "tor_resolve",
    }
)


EXPECTED_NETWORK_OBSERVE_METHODS: frozenset[str] = frozenset(
    {
        "browser_network_requests",
        "browser_network_request",
    }
)


EXPECTED_VISION_METHODS: frozenset[str] = frozenset(
    {
        "browser_mouse_move_xy",
        "browser_mouse_click_xy",
        "browser_mouse_down",
        "browser_mouse_up",
        "browser_mouse_drag_xy",
        "browser_mouse_wheel",
        "browser_resize",
    }
)


EXPECTED_HIGHLIGHT_METHODS: frozenset[str] = frozenset(
    {
        "browser_highlight",
        "browser_hide_highlight",
    }
)


EXPECTED_TOR_ROUTING_METHODS: frozenset[str] = frozenset(
    {
        "tor_set_exit_country",
        "tor_set_exit_nodes",
        "tor_clear_exit_policy",
    }
)


EXPECTED_UNSAFE_METHODS: frozenset[str] = frozenset(
    {
        "browser_chrome_evaluate_unsafe",
        "browser_run_python_unsafe",
        "tor_control_command_unsafe",
    }
)


EXPECTED_PDF_METHODS: frozenset[str] = frozenset(
    {
        "browser_pdf_save",
    }
)


EXPECTED_HTTP_OVER_TOR_METHODS: frozenset[str] = frozenset(
    {
        "tor_http_request",
        "tor_http_sequence",
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


def test_registered_methods_state_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"state"})
    assert set(methods.keys()) == EXPECTED_STATE_METHODS


def test_registered_methods_extract_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"extract"})
    assert set(methods.keys()) == EXPECTED_EXTRACT_METHODS


def test_registered_methods_diagnostics_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"diagnostics"})
    assert set(methods.keys()) == EXPECTED_DIAGNOSTICS_METHODS


def test_registered_methods_tor_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"tor"})
    assert set(methods.keys()) == EXPECTED_TOR_METHODS


def test_registered_methods_network_observe_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"network-observe"})
    assert set(methods.keys()) == EXPECTED_NETWORK_OBSERVE_METHODS


def test_registered_methods_vision_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"vision"})
    assert set(methods.keys()) == EXPECTED_VISION_METHODS


def test_registered_methods_highlight_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"highlight"})
    assert set(methods.keys()) == EXPECTED_HIGHLIGHT_METHODS


def test_registered_methods_tor_routing_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"tor-routing"})
    assert set(methods.keys()) == EXPECTED_TOR_ROUTING_METHODS


def test_registered_methods_unsafe_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"unsafe"})
    assert set(methods.keys()) == EXPECTED_UNSAFE_METHODS


def test_registered_methods_pdf_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"pdf"})
    assert set(methods.keys()) == EXPECTED_PDF_METHODS


def test_registered_methods_http_over_tor_matches_expected_set() -> None:
    methods = registered_methods(TorBrowserDriver, {"http-over-tor"})
    assert set(methods.keys()) == EXPECTED_HTTP_OVER_TOR_METHODS


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
