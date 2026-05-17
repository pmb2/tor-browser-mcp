"""MCP server layer for :mod:`torbrowser_driver`.

Exposes the capability-tagged driver methods as MCP tools over the
official ``mcp`` Python SDK. The public surface is small: :func:`main`
backs the ``torbrowser-mcp`` console script, :func:`run_server` runs the
asyncio event loop against an already-built :class:`DriverConfig`, and
:class:`ServerOptions` / :class:`ToolContext` are the helper types
``--tool-module`` extension modules consume.
"""

from __future__ import annotations

from .cli import main
from .server import ServerOptions, build_server, run_server
from .tool_module import ToolContext, load_tool_module

__version__ = "0.0.0"

__all__ = [
    "ServerOptions",
    "ToolContext",
    "__version__",
    "build_server",
    "load_tool_module",
    "main",
    "run_server",
]
