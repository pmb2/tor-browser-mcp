"""Unit tests for the signature -> JSON schema converter."""

from __future__ import annotations

from typing import Annotated, Any, Literal, NotRequired, TypedDict

import pytest

from torbrowser_driver import TorBrowserDriver
from torbrowser_mcp.schema import _annotation_to_schema, tool_description, tool_input_schema


class SchemaItem(TypedDict):
    selector: str
    value: str | bool


def test_tool_input_schema_no_params() -> None:
    def fn() -> dict[str, Any]:
        """Do nothing useful."""
        return {}

    schema = tool_input_schema(fn)
    assert schema["type"] == "object"
    assert schema["properties"] == {}
    assert "required" not in schema
    assert schema["additionalProperties"] is False


def test_tool_input_schema_mixed_required_and_optional() -> None:
    def fn(a: str, b: int = 3) -> dict[str, Any]:
        """Mix of required and default params."""
        return {"a": a, "b": b}

    schema = tool_input_schema(fn)
    assert schema["properties"]["a"] == {"type": "string"}
    assert schema["properties"]["b"] == {"type": "integer"}
    assert schema["required"] == ["a"]


def test_tool_input_schema_optional_not_required() -> None:
    def fn(name: str | None) -> dict[str, Any]:
        """Optional[str] argument with no default."""
        return {"name": name}

    schema = tool_input_schema(fn)
    assert schema["properties"]["name"] == {"type": "string"}
    assert "required" not in schema


def test_tool_input_schema_list_of_strings() -> None:
    def fn(items: list[str]) -> dict[str, Any]:
        """List of strings."""
        return {"items": items}

    schema = tool_input_schema(fn)
    assert schema["properties"]["items"] == {
        "type": "array",
        "items": {"type": "string"},
    }


def test_tool_input_schema_pep604_optional() -> None:
    def fn(name: str | None = None) -> dict[str, Any]:
        """PEP 604 optional."""
        return {"name": name}

    schema = tool_input_schema(fn)
    assert schema["properties"]["name"] == {"type": "string"}
    assert "name" not in schema.get("required", [])


def test_tool_input_schema_literal_enum() -> None:
    def fn(action: Literal["list", "new"]) -> dict[str, Any]:
        """Literal enum."""
        return {"action": action}

    schema = tool_input_schema(fn)
    assert schema["properties"]["action"] == {
        "type": "string",
        "enum": ["list", "new"],
    }


def test_tool_input_schema_typed_dict_array() -> None:
    def fn(items: list[SchemaItem]) -> dict[str, Any]:
        """TypedDict item array."""
        return {"items": items}

    schema = tool_input_schema(fn)
    item_schema = schema["properties"]["items"]["items"]
    assert item_schema["type"] == "object"
    assert item_schema["properties"]["selector"] == {"type": "string"}
    assert item_schema["properties"]["value"] == {
        "anyOf": [{"type": "string"}, {"type": "boolean"}]
    }
    assert item_schema["required"] == ["selector", "value"]
    assert item_schema["additionalProperties"] is False


def test_tool_input_schema_dict_of_any() -> None:
    def fn(payload: dict[str, Any]) -> dict[str, Any]:
        """Dict argument."""
        return payload

    schema = tool_input_schema(fn)
    assert schema["properties"]["payload"]["type"] == "object"


def test_tool_input_schema_var_args_rejected() -> None:
    def fn(*args: int) -> None:
        """Bad signature."""

    with pytest.raises(ValueError):
        tool_input_schema(fn)


def test_tool_input_schema_var_kwargs_rejected() -> None:
    def fn(**kwargs: int) -> None:
        """Bad signature."""

    with pytest.raises(ValueError):
        tool_input_schema(fn)


def test_tool_input_schema_bool_and_float() -> None:
    def fn(flag: bool, ratio: float) -> None:
        """Bool and float."""

    schema = tool_input_schema(fn)
    assert schema["properties"]["flag"] == {"type": "boolean"}
    assert schema["properties"]["ratio"] == {"type": "number"}


def test_tool_input_schema_unannotated_param_is_open_schema() -> None:
    def fn(x) -> None:  # type: ignore[no-untyped-def]
        """Unannotated."""

    schema = tool_input_schema(fn)
    assert schema["properties"]["x"] == {}
    assert schema["required"] == ["x"]


def test_tool_input_schema_real_browser_navigate_signature() -> None:
    schema = tool_input_schema(TorBrowserDriver.browser_navigate)
    assert schema["properties"] == {"url": {"type": "string"}}
    assert schema["required"] == ["url"]
    assert schema["additionalProperties"] is False
    assert "self" not in schema["properties"]


def test_tool_input_schema_real_browser_wait_for_signature() -> None:
    schema = tool_input_schema(TorBrowserDriver.browser_wait_for)
    props = schema["properties"]
    assert props["text"] == {"type": "string"}
    assert props["selector"] == {"type": "string"}
    assert props["timeout"] == {"type": "number"}
    assert "timeout" not in schema.get("required", [])
    assert "text" not in schema.get("required", [])


def test_tool_input_schema_real_browser_fill_form_signature() -> None:
    schema = tool_input_schema(TorBrowserDriver.browser_fill_form)
    fields = schema["properties"]["fields"]
    assert fields["type"] == "array"
    item_schema = fields["items"]
    assert item_schema["properties"]["selector"] == {"type": "string"}
    assert item_schema["properties"]["value"] == {
        "anyOf": [{"type": "string"}, {"type": "boolean"}]
    }
    assert item_schema["required"] == ["selector", "value"]


def test_tool_input_schema_real_tor_http_sequence_request_schema() -> None:
    schema = tool_input_schema(TorBrowserDriver.tor_http_sequence)
    item_schema = schema["properties"]["requests"]["items"]
    assert item_schema["required"] == ["url"]
    assert item_schema["properties"]["method"] == {
        "type": "string",
        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    }
    assert item_schema["properties"]["headers"] == {
        "type": "object",
        "additionalProperties": {"type": "string"},
    }


def test_tool_input_schema_real_browser_tabs_action_enum() -> None:
    schema = tool_input_schema(TorBrowserDriver.browser_tabs)
    assert schema["properties"]["action"] == {
        "type": "string",
        "enum": ["list", "new", "select", "close"],
    }


def test_tool_input_schema_real_string_enums() -> None:
    cases = {
        "browser_network_request": ("part", ["headers", "body"]),
        "browser_cookie_set": ("same_site", ["Strict", "Lax", "None"]),
        "browser_console_messages": ("level", ["INFO", "WARNING", "SEVERE"]),
        "browser_mouse_click_xy": ("button", ["left", "middle", "right"]),
        "browser_click": ("button", ["left", "right"]),
        "tor_http_request": (
            "method",
            ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        ),
    }
    for tool_name, (prop_name, values) in cases.items():
        schema = tool_input_schema(getattr(TorBrowserDriver, tool_name))
        assert schema["properties"][prop_name] == {
            "type": "string",
            "enum": values,
        }


def test_tool_input_schema_real_browser_click_modifier_enum() -> None:
    schema = tool_input_schema(TorBrowserDriver.browser_click)
    modifiers = schema["properties"]["modifiers"]
    assert modifiers == {
        "type": "array",
        "items": {
            "type": "string",
            "enum": ["CTRL", "CONTROL", "SHIFT", "ALT", "META", "COMMAND"],
        },
    }


def test_tool_input_schema_real_output_control_additions() -> None:
    expected = {
        "browser_cookie_list": {"limit", "filename"},
        "browser_localstorage_list": {"limit", "filename"},
        "browser_sessionstorage_list": {"limit", "filename"},
        "browser_downloads_list": {"limit"},
        "browser_frames": {"limit"},
        "tor_circuit_status": {"limit"},
        "tor_stream_status": {"limit"},
        "tor_entry_guards": {"limit"},
        "tor_get_info": {"filename"},
        "browser_intercept_flows": {"filename"},
        "browser_intercept_flow": {"filename"},
        "browser_route_list": {"limit", "filename"},
    }
    for tool_name, names in expected.items():
        schema = tool_input_schema(getattr(TorBrowserDriver, tool_name))
        assert names <= set(schema["properties"])


def test_tool_description_first_paragraph() -> None:
    def fn() -> None:
        """First line.

        Second paragraph that should not appear.
        """

    assert tool_description(fn) == "First line."


def test_tool_description_fallback_to_name() -> None:
    def fn() -> None:
        pass

    assert tool_description(fn).endswith("fn")


def test_tool_description_handles_multiline_first_paragraph() -> None:
    def fn() -> None:
        """First paragraph
        wraps across two lines.

        Second paragraph.
        """

    assert tool_description(fn) == "First paragraph wraps across two lines."


def test_annotated_description_passthrough() -> None:
    def fn(x: Annotated[str, "the selector"]) -> None:
        """Annotated description on a primitive."""

    schema = tool_input_schema(fn)
    assert schema["properties"]["x"] == {
        "type": "string",
        "description": "the selector",
    }


def test_annotated_non_string_metadata_is_ignored() -> None:
    def fn(x: Annotated[str, 42]) -> None:
        """Annotated with non-string metadata."""

    schema = tool_input_schema(fn)
    assert schema["properties"]["x"] == {"type": "string"}


def test_annotated_optional_is_not_required() -> None:
    def fn(name: Annotated[str | None, "the name"]) -> None:
        """Annotated wrapping Optional must still be optional."""

    schema = tool_input_schema(fn)
    assert schema["properties"]["name"] == {
        "type": "string",
        "description": "the name",
    }
    assert "name" not in schema.get("required", [])


def test_mixed_type_literal_emits_enum_without_type() -> None:
    assert _annotation_to_schema(Literal["a", 1]) == {"enum": ["a", 1]}


class _TotalFalseDict(TypedDict, total=False):
    name: str
    count: int


def test_typed_dict_total_false_has_no_required() -> None:
    schema = _annotation_to_schema(_TotalFalseDict)
    assert schema["type"] == "object"
    assert set(schema["properties"]) == {"name", "count"}
    assert "required" not in schema


class _NotRequiredDict(TypedDict):
    name: str
    count: NotRequired[int]


def test_typed_dict_not_required_field_keeps_property_type() -> None:
    schema = _annotation_to_schema(_NotRequiredDict)
    assert schema["properties"]["count"] == {"type": "integer"}
    assert schema["required"] == ["name"]
