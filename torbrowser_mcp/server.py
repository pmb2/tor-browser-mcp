"""MCP server build and lifecycle.

Builds a low-level :class:`mcp.server.Server` whose tool surface is the
union of :func:`registered_methods` against a :class:`TorBrowserDriver`
plus any tools added by ``--tool-module`` extension modules. The sync
driver methods are dispatched via :func:`asyncio.to_thread` so they never
block the event loop. Tool exceptions are converted to MCP error
responses rather than propagated, so the server stays up across faults.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from torbrowser_driver import (
    DriverConfig,
    TorBrowserDriver,
    registered_methods,
)

from .schema import tool_description, tool_input_schema


log = logging.getLogger(__name__)


PROXY_INTERCEPT_STARTUP_WARNING = (
    "WARNING: proxy-intercept enabled. Tor Browser's per-first-party\n"
    "circuit isolation is disabled for this session, and the local\n"
    "intercept proxy sees every page's plaintext. Decrypted bodies are\n"
    "held in memory and may be written to disk by browser_intercept_save.\n"
    "This is opt-in and intended for adversary-emulation, detection-\n"
    "engineering, and protocol-reverse-engineering use cases against\n"
    "content you control or are authorised to inspect. It is not a\n"
    "stealth mode."
)


@dataclass(frozen=True)
class ServerOptions:
    """Server-side options that are not part of :class:`DriverConfig`.

    Attributes:
        tool_modules: ``--tool-module`` paths to load after the driver is
            up.
        log_level: Root log level for the server process.
        transport: MCP transport name. Only ``"stdio"`` is implemented.
    """

    tool_modules: tuple[Path, ...] = field(default_factory=tuple)
    log_level: str = "info"
    transport: str = "stdio"


@dataclass
class _RegisteredTool:
    name: str
    description: str
    schema: dict[str, Any]
    handler: Callable[..., Any]


class _ToolRegistry:
    """In-memory tool table consumed by the server handlers."""

    def __init__(self) -> None:
        self._tools: dict[str, _RegisteredTool] = {}

    def add(
        self,
        name: str,
        handler: Callable[..., Any],
        description: str,
        schema: dict[str, Any],
    ) -> None:
        if name in self._tools:
            raise ValueError(f"tool {name!r} already registered")
        self._tools[name] = _RegisteredTool(
            name=name,
            description=description,
            schema=schema,
            handler=handler,
        )

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name=t.name,
                description=t.description,
                inputSchema=t.schema,
            )
            for t in self._tools.values()
        ]

    def get(self, name: str) -> _RegisteredTool | None:
        return self._tools.get(name)


def _make_driver_handler(driver: Any, method_name: str) -> Callable[..., Any]:
    """Build the async dispatch shim for a driver method.

    The shim calls the bound method via :func:`asyncio.to_thread` so the
    sync Selenium/stem call never blocks the event loop.
    """

    async def handler(**kwargs: Any) -> Any:
        bound = getattr(driver, method_name)
        return await asyncio.to_thread(bound, **kwargs)

    handler.__name__ = f"{method_name}_handler"
    return handler


def _make_user_handler(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap an ``add_tool``-supplied function in an async dispatch shim.

    Async functions pass through; sync functions are routed via
    :func:`asyncio.to_thread`.
    """

    if inspect.iscoroutinefunction(fn):
        async def async_handler(**kwargs: Any) -> Any:
            return await fn(**kwargs)
        return async_handler

    async def sync_handler(**kwargs: Any) -> Any:
        return await asyncio.to_thread(fn, **kwargs)

    return sync_handler


def _format_result(result: Any) -> list[TextContent]:
    """Serialise a tool result into MCP ``TextContent`` blocks.

    A dict is JSON-encoded; a dict carrying a ``path`` field gets a
    second informational ``TextContent`` block naming the artifact path.
    Non-dict results are stringified as-is for the unstructured channel.
    """

    blocks: list[TextContent] = []
    if isinstance(result, dict):
        payload = json.dumps(result, ensure_ascii=False, indent=2)
        blocks.append(TextContent(type="text", text=payload))
        artifact = result.get("path") if isinstance(result, dict) else None
        if isinstance(artifact, str):
            blocks.append(
                TextContent(type="text", text=f"Artifact written to {artifact}")
            )
    else:
        blocks.append(TextContent(type="text", text=str(result)))
    return blocks


def build_server(
    driver: Any,
    enabled_caps: Iterable[str],
    *,
    server_name: str = "tor-browser-mcp",
    extra_tools: Iterable[tuple[str, Callable[..., Any], str | None, dict[str, Any] | None]] = (),
) -> tuple[Server, _ToolRegistry]:
    """Construct an :class:`mcp.server.Server` against ``driver``.

    Returns the server plus the populated registry. The registry is
    exposed so callers (and tests) can inspect what got registered. Tool
    handlers dispatch the sync driver methods through
    :func:`asyncio.to_thread` and convert exceptions into MCP error
    responses (``isError=True``).
    """

    enabled_set = frozenset(enabled_caps)
    if "proxy-intercept" in enabled_set:
        print(PROXY_INTERCEPT_STARTUP_WARNING, file=sys.stderr)

    registry = _ToolRegistry()

    for tool_name, unbound in registered_methods(TorBrowserDriver, enabled_set).items():
        schema = tool_input_schema(unbound)
        description = tool_description(unbound)
        handler = _make_driver_handler(driver, tool_name)
        registry.add(tool_name, handler, description, schema)

    for name, fn, description, schema in extra_tools:
        if schema is None:
            schema = tool_input_schema(fn)
        if description is None:
            description = tool_description(fn)
        registry.add(name, _make_user_handler(fn), description, schema)

    server: Server = Server(server_name)

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return registry.list_tools()

    @server.call_tool()
    async def _call_tool(
        name: str, arguments: dict[str, Any]
    ) -> list[TextContent] | CallToolResult:
        entry = registry.get(name)
        if entry is None:
            return CallToolResult(
                content=[TextContent(type="text", text=f"unknown tool {name!r}")],
                isError=True,
            )

        try:
            result = await entry.handler(**(arguments or {}))
        except Exception as exc:
            text = f"{type(exc).__name__}: {exc}"
            return CallToolResult(
                content=[TextContent(type="text", text=text)],
                isError=True,
            )

        return _format_result(result)

    return server, registry


def _registry_add_tool(registry: _ToolRegistry) -> Callable[..., None]:
    """Adapter so a ``--tool-module`` can call ``add_tool(name, fn, ...)``."""

    def add_tool(
        name: str,
        fn: Callable[..., Any],
        description: str | None = None,
        schema: dict[str, Any] | None = None,
    ) -> None:
        if schema is None:
            schema = tool_input_schema(fn)
        if description is None:
            description = tool_description(fn)
        registry.add(name, _make_user_handler(fn), description, schema)

    return add_tool


async def run_server(config: DriverConfig, options: ServerOptions) -> None:
    """Boot the driver, build the MCP server, and serve until shutdown.

    Lifecycle: the driver is entered as a context manager around the full
    server run, so the browser is up before the first MCP request and is
    torn down on shutdown (including on cancellation). ``--tool-module``
    files are loaded after the driver is up and before the server starts
    accepting requests.
    """

    if options.transport != "stdio":
        raise NotImplementedError(
            f"transport {options.transport!r} is not implemented; "
            "only 'stdio' is supported today"
        )

    from .tool_module import ToolContext, load_tool_module

    with TorBrowserDriver(config) as driver:
        server, registry = build_server(driver, config.enabled_caps)

        if options.tool_modules:
            add_tool = _registry_add_tool(registry)
            ctx = ToolContext(
                driver=driver,
                config=config,
                path_policy=config.path_policy,
                output_dir=config.path_policy.output_dir,
                add_tool=add_tool,
            )
            for module_path in options.tool_modules:
                added = load_tool_module(module_path, ctx)
                log.info("tool-module %s registered: %s", module_path, added)

        init_options = InitializationOptions(
            server_name="tor-browser-mcp",
            server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(),
                experimental_capabilities={},
            ),
        )

        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, init_options)
