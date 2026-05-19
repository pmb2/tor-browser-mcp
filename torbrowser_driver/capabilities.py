"""Capability registry for driver methods.

Driver methods are tagged with the capability group they belong to via the
:func:`capability` decorator. The higher MCP layer calls
:func:`registered_methods` against the driver class plus the set of enabled
capability groups to decide which methods to surface as tools. The driver
class itself does not enforce capability gating at call time; methods are
always callable from Python regardless of ``DriverConfig.enabled_caps``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .exceptions import DriverConfigError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

DEFAULT_CAPABILITIES: frozenset[str] = frozenset(
    {"core", "state", "extract", "diagnostics", "tor", "network-observe"}
)

OPTIONAL_CAPABILITIES: frozenset[str] = frozenset(
    {
        "vision",
        "pdf",
        "highlight",
        "http-over-tor",
        "tor-routing",
        "helper-extension",
        "proxy-intercept",
        "unsafe",
    }
)

KNOWN_CAPABILITIES: frozenset[str] = DEFAULT_CAPABILITIES | OPTIONAL_CAPABILITIES


def capability(
    name: str, *, tool_name: str | None = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Tag a method with its capability group and optional tool-facing name.

    Attaches ``_capability`` and (when supplied) ``_tool_name`` attributes to
    the wrapped function so :func:`registered_methods` can discover it. The
    decorator validates ``name`` against :data:`KNOWN_CAPABILITIES` at
    decoration time, raising :class:`DriverConfigError` for unknown groups.
    """

    if name not in KNOWN_CAPABILITIES:
        raise DriverConfigError(
            f"unknown capability {name!r}; known: "
            f"{sorted(KNOWN_CAPABILITIES)}"
        )

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        func._capability = name  # type: ignore[attr-defined]
        if tool_name is not None:
            func._tool_name = tool_name  # type: ignore[attr-defined]
        return func

    return decorator


def registered_methods(
    cls: type, enabled_caps: Iterable[str]
) -> dict[str, Callable[..., Any]]:
    """Return ``{tool_name: unbound_method}`` for capability-tagged methods.

    Walks ``cls.__mro__`` so methods declared on mixin bases are included.
    A method's tool-facing name defaults to its Python attribute name but
    can be overridden via ``capability(..., tool_name=...)``. Methods are
    filtered to those whose ``_capability`` value appears in
    ``enabled_caps``.
    """

    enabled = frozenset(enabled_caps)
    result: dict[str, Callable[..., Any]] = {}

    for base in reversed(cls.__mro__):
        for attr_name, value in base.__dict__.items():
            cap = getattr(value, "_capability", None)
            if cap is None:
                continue
            if cap not in enabled:
                continue
            tool_name = getattr(value, "_tool_name", None) or attr_name
            current = getattr(cls, attr_name, value)
            result[tool_name] = current

    return result
