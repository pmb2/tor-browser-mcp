"""Tests for the MCP server tool registration and dispatch."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from mcp.types import CallToolResult, TextContent

from torbrowser_driver import TorBrowserDriver, registered_methods
from torbrowser_mcp.server import build_server


def _run(coro):
    return asyncio.run(coro)


def test_registered_tool_names_match_driver_core() -> None:
    driver = MagicMock(spec=TorBrowserDriver)
    server, registry = build_server(driver, {"core"})
    expected = set(registered_methods(TorBrowserDriver, {"core"}).keys())
    assert set(registry.names()) == expected


def test_list_tools_returns_tool_objects() -> None:
    driver = MagicMock(spec=TorBrowserDriver)
    server, registry = build_server(driver, {"core"})
    tools = registry.list_tools()
    assert tools, "expected at least one core tool"
    assert any(t.name == "browser_navigate" for t in tools)
    nav = next(t for t in tools if t.name == "browser_navigate")
    assert nav.inputSchema["properties"]["url"] == {"type": "string"}
    assert nav.inputSchema["required"] == ["url"]


def test_call_tool_dispatches_to_driver() -> None:
    driver = MagicMock(spec=TorBrowserDriver)
    driver.browser_navigate.return_value = {"url": "https://example.com", "title": "x"}
    server, registry = build_server(driver, {"core"})

    entry = registry.get("browser_navigate")
    assert entry is not None
    result = _run(entry.handler(url="https://example.com"))
    driver.browser_navigate.assert_called_once_with(url="https://example.com")
    assert result == {"url": "https://example.com", "title": "x"}


def test_call_tool_via_server_handler_returns_text_content() -> None:
    driver = MagicMock(spec=TorBrowserDriver)
    driver.browser_navigate.return_value = {"url": "https://example.com", "title": "x"}
    server, _ = build_server(driver, {"core"})

    handler = _call_tool_handler(server)
    blocks = _run(handler("browser_navigate", {"url": "https://example.com"}))
    assert isinstance(blocks, list)
    assert all(isinstance(b, TextContent) for b in blocks)
    payload = json.loads(blocks[0].text)
    assert payload == {"url": "https://example.com", "title": "x"}


def test_call_tool_artifact_path_emits_second_block(tmp_path) -> None:
    driver = MagicMock(spec=TorBrowserDriver)
    driver.browser_take_screenshot.return_value = {
        "path": str(tmp_path / "shot.png"),
        "bytes": 42,
    }
    server, _ = build_server(driver, {"core"})
    handler = _call_tool_handler(server)
    blocks = _run(handler("browser_take_screenshot", {}))
    assert len(blocks) == 2
    assert "Artifact written to" in blocks[1].text


def test_call_tool_exception_becomes_error_result() -> None:
    driver = MagicMock(spec=TorBrowserDriver)
    driver.browser_navigate.side_effect = RuntimeError("nope")
    server, _ = build_server(driver, {"core"})

    handler = _call_tool_handler(server)
    result = _run(handler("browser_navigate", {"url": "x"}))
    assert isinstance(result, CallToolResult)
    assert result.isError is True
    assert "RuntimeError" in result.content[0].text
    assert "nope" in result.content[0].text


def test_unknown_tool_returns_error_result() -> None:
    driver = MagicMock(spec=TorBrowserDriver)
    server, _ = build_server(driver, {"core"})
    handler = _call_tool_handler(server)
    result = _run(handler("does_not_exist", {}))
    assert isinstance(result, CallToolResult)
    assert result.isError is True


def test_extra_tools_registered() -> None:
    driver = MagicMock(spec=TorBrowserDriver)

    def hello() -> dict:
        return {"ok": True}

    server, registry = build_server(
        driver,
        {"core"},
        extra_tools=[("hello", hello, "say hello", None)],
    )
    assert "hello" in registry.names()
    entry = registry.get("hello")
    assert entry is not None
    assert entry.description == "say hello"
    assert _run(entry.handler()) == {"ok": True}


def test_enabled_caps_filter() -> None:
    driver = MagicMock(spec=TorBrowserDriver)
    _, core_only = build_server(driver, {"core"})
    _, with_extract = build_server(driver, {"core", "extract"})
    assert set(with_extract.names()) > set(core_only.names())


# Helpers -------------------------------------------------------------

def _call_tool_handler(server):
    """Pull the registered call-tool handler off the low-level server."""

    from mcp import types

    request_handler = server.request_handlers[types.CallToolRequest]

    async def invoke(name: str, arguments: dict):
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name=name, arguments=arguments),
        )
        server_result = await request_handler(req)
        inner = server_result.root
        if isinstance(inner, types.CallToolResult):
            if inner.isError:
                return inner
            return list(inner.content)
        return inner

    return invoke
