"""Unit tests for the signature -> JSON schema converter."""

from __future__ import annotations

from typing import Any, Optional

import pytest

from torbrowser_driver import TorBrowserDriver
from torbrowser_mcp.schema import tool_description, tool_input_schema


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
    def fn(name: Optional[str]) -> dict[str, Any]:
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
    assert "text" in props
    assert "selector" in props
    assert "timeout" in props
    assert props["timeout"] == {"type": "number"}
    assert "timeout" not in schema.get("required", [])
    assert "text" not in schema.get("required", [])


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
