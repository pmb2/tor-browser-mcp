"""Convert :mod:`inspect`-style call signatures to MCP JSON schemas.

The MCP tool registration loop needs a JSON schema for every tool. This
module derives one mechanically from a callable's signature and type
annotations, plus a short description pulled from the docstring. Only the
type forms that appear in the driver's primitive surface are supported -
``str``, ``int``, ``float``, ``bool``, ``list[T]``, ``dict[str, T]``,
``Optional[T]``, ``Any`` - and ``*args`` / ``**kwargs`` are rejected so a
misconfigured primitive surfaces loudly rather than producing a silently
broken tool.
"""

from __future__ import annotations

import inspect
import typing
from typing import Any, Callable, Union, get_args, get_origin


_PRIMITIVE_MAP: dict[type, dict[str, Any]] = {
    str: {"type": "string"},
    int: {"type": "integer"},
    float: {"type": "number"},
    bool: {"type": "boolean"},
}


def _unwrap_optional(annotation: Any) -> tuple[Any, bool]:
    """Return ``(inner_type, is_optional)``.

    A ``X | None`` / ``Optional[X]`` annotation collapses to ``X`` with
    ``is_optional=True``. Non-optional annotations pass through unchanged.
    A bare ``None`` annotation is treated as optional ``Any``.
    """

    origin = get_origin(annotation)
    if origin is Union or origin is typing.Union:
        args = [a for a in get_args(annotation) if a is not type(None)]
        is_optional = len(args) != len(get_args(annotation))
        if not args:
            return Any, True
        if len(args) == 1:
            return args[0], is_optional
        return Union[tuple(args)], is_optional  # type: ignore[return-value]
    return annotation, False


def _annotation_to_schema(annotation: Any) -> dict[str, Any]:
    """Map a single Python annotation to a JSON schema fragment."""

    if annotation is inspect.Parameter.empty or annotation is Any:
        return {}

    inner, _ = _unwrap_optional(annotation)
    if inner is Any:
        return {}

    if isinstance(inner, type) and inner in _PRIMITIVE_MAP:
        return dict(_PRIMITIVE_MAP[inner])

    origin = get_origin(inner)
    args = get_args(inner)

    if origin in (list, tuple, set, frozenset):
        item = args[0] if args else Any
        return {"type": "array", "items": _annotation_to_schema(item)}

    if origin is dict:
        value_t = args[1] if len(args) == 2 else Any
        value_schema = _annotation_to_schema(value_t)
        result: dict[str, Any] = {"type": "object"}
        if value_schema:
            result["additionalProperties"] = value_schema
        return result

    if origin is Union or origin is typing.Union:
        sub = [_annotation_to_schema(a) for a in args if a is not type(None)]
        sub = [s for s in sub if s]
        if not sub:
            return {}
        if len(sub) == 1:
            return sub[0]
        return {"anyOf": sub}

    return {}


def tool_description(fn: Callable[..., Any]) -> str:
    """Return the first non-empty paragraph of ``fn``'s docstring.

    Falls back to the function's qualified name when no docstring is
    present.
    """

    doc = inspect.getdoc(fn)
    if doc:
        paragraph: list[str] = []
        for line in doc.splitlines():
            if line.strip():
                paragraph.append(line.strip())
            elif paragraph:
                break
        if paragraph:
            return " ".join(paragraph)
    return getattr(fn, "__qualname__", getattr(fn, "__name__", "tool"))


def _resolve_hints(fn: Callable[..., Any]) -> dict[str, Any]:
    try:
        return typing.get_type_hints(fn, include_extras=False)
    except Exception:
        return {}


def tool_input_schema(fn: Callable[..., Any]) -> dict[str, Any]:
    """Build a JSON schema for ``fn``'s call signature.

    The result is shaped as ``{"type": "object", "properties": {...},
    "required": [...], "additionalProperties": false}``. ``self`` is
    dropped. Parameters with defaults are not required. ``Optional[T]``
    parameters are not required even when no default is set. ``*args`` and
    ``**kwargs`` raise :class:`ValueError`.
    """

    sig = inspect.signature(fn)
    hints = _resolve_hints(fn)

    properties: dict[str, Any] = {}
    required: list[str] = []

    for name, param in sig.parameters.items():
        if name == "self":
            continue
        if param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            raise ValueError(
                f"tool {fn.__qualname__} uses *args/**kwargs; not supported"
            )

        annotation = hints.get(name, param.annotation)
        _, is_optional = _unwrap_optional(annotation)
        prop = _annotation_to_schema(annotation)
        properties[name] = prop

        has_default = param.default is not inspect.Parameter.empty
        if not has_default and not is_optional:
            required.append(name)

    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema
