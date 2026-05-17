"""``--tool-module`` loader.

The CLI accepts paths to trusted Python files. Each file must expose a
top-level ``register(context)`` callable. The loader imports the file via
:mod:`importlib.util` and invokes ``register`` with a :class:`ToolContext`
that gives the module access to the live driver and a function to add new
tools to the server.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from torbrowser_driver import (
    DriverConfig,
    DriverConfigError,
    PathPolicy,
    TorBrowserDriver,
)


AddToolFn = Callable[[str, Callable[..., Any], "str | None", "dict[str, Any] | None"], None]


@dataclass(frozen=True)
class ToolContext:
    """Handles exposed to a ``--tool-module`` ``register(context)`` function.

    Attributes:
        driver: The live :class:`TorBrowserDriver` (already entered as a
            context manager). Tool functions may call any of its methods,
            including ones not surfaced as MCP tools.
        config: The :class:`DriverConfig` the driver was started with.
        path_policy: Convenience alias for ``config.path_policy``.
        output_dir: Convenience alias for ``config.path_policy.output_dir``.
        add_tool: Callable to register an additional MCP tool. Signature
            is ``add_tool(name, fn, description=None, schema=None)``.
    """

    driver: TorBrowserDriver
    config: DriverConfig
    path_policy: PathPolicy
    output_dir: Path
    add_tool: AddToolFn


def load_tool_module(path: Path, context: ToolContext) -> list[str]:
    """Import the module at ``path`` and call ``register(context)``.

    Returns the list of tool names the module registered (captured by
    wrapping the supplied ``add_tool`` callback). Raises
    :class:`DriverConfigError` if the file cannot be loaded or does not
    expose a top-level ``register`` function.
    """

    if not path.is_file():
        raise DriverConfigError(f"tool module {path!s} does not exist")

    spec = importlib.util.spec_from_file_location(
        f"torbrowser_mcp._tool_module_{path.stem}", path
    )
    if spec is None or spec.loader is None:
        raise DriverConfigError(
            f"tool module {path!s} could not be loaded (no import spec)"
        )

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise DriverConfigError(
            f"tool module {path!s} failed to import: {exc}"
        ) from exc

    register = getattr(module, "register", None)
    if not callable(register):
        raise DriverConfigError(
            f"tool module {path!s} is missing a top-level register(context) function"
        )

    added: list[str] = []
    original_add_tool = context.add_tool

    def tracking_add_tool(
        name: str,
        fn: Callable[..., Any],
        description: str | None = None,
        schema: dict[str, Any] | None = None,
    ) -> None:
        original_add_tool(name, fn, description, schema)
        added.append(name)

    wrapped_context = ToolContext(
        driver=context.driver,
        config=context.config,
        path_policy=context.path_policy,
        output_dir=context.output_dir,
        add_tool=tracking_add_tool,
    )

    register(wrapped_context)
    return added
