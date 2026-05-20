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
import types
import typing
from typing import Any, Union, get_args, get_origin

from typing_extensions import NotRequired, Required

if typing.TYPE_CHECKING:
    from collections.abc import Callable

_PRIMITIVE_MAP: dict[type, dict[str, Any]] = {
    str: {"type": "string"},
    int: {"type": "integer"},
    float: {"type": "number"},
    bool: {"type": "boolean"},
}


def _is_union_origin(origin: Any) -> bool:
    return origin is typing.Union or origin is types.UnionType


def _unwrap_optional(annotation: Any) -> tuple[Any, bool]:
    """Return ``(inner_type, is_optional)``.

    A ``X | None`` / ``Optional[X]`` annotation collapses to ``X`` with
    ``is_optional=True``. ``Annotated[Optional[X], ...]`` is unwrapped first
    so the description metadata never hides the optional union. Non-optional
    annotations pass through unchanged. A bare ``None`` annotation is
    treated as optional ``Any``.
    """

    if get_origin(annotation) is typing.Annotated:
        annotation = get_args(annotation)[0]

    origin = get_origin(annotation)
    if _is_union_origin(origin):
        raw_args = get_args(annotation)
        args = [a for a in raw_args if a is not type(None)]
        is_optional = len(args) != len(raw_args)
        if not args:
            return Any, True
        if len(args) == 1:
            return args[0], is_optional
        return Union[tuple(args)], is_optional  # noqa: UP007  # dynamic Union over variable-length tuple
    return annotation, False


def _annotation_to_schema(annotation: Any) -> dict[str, Any]:
    """Map a single Python annotation to a JSON schema fragment."""

    if annotation is inspect.Parameter.empty or annotation is Any:
        return {}

    origin = get_origin(annotation)
    if origin is typing.Annotated:
        base, *metadata = get_args(annotation)
        result = _annotation_to_schema(base)
        for item in metadata:
            if isinstance(item, str):
                result.setdefault("description", item)
                break
        return result

    inner, _ = _unwrap_optional(annotation)
    if inner is Any:
        return {}

    if isinstance(inner, type) and inner in _PRIMITIVE_MAP:
        return dict(_PRIMITIVE_MAP[inner])

    if typing.is_typeddict(inner):
        hints = typing.get_type_hints(inner, include_extras=True)
        properties = {
            name: _annotation_to_schema(value)
            for name, value in hints.items()
        }
        td_result: dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        raw_required: frozenset[str] = getattr(inner, "__required_keys__", frozenset())
        required = sorted(
            name for name in raw_required
            if get_origin(hints.get(name)) is not NotRequired
        )
        if required:
            td_result["required"] = required
        return td_result

    origin = get_origin(inner)
    args = get_args(inner)

    if origin in (NotRequired, Required):
        return _annotation_to_schema(args[0])

    if origin is typing.Literal:
        values = list(args)
        literal_result: dict[str, Any] = {"enum": values}
        value_types = {type(v) for v in values}
        if len(value_types) == 1:
            value_type = next(iter(value_types))
            primitive = _PRIMITIVE_MAP.get(value_type)
            if primitive:
                literal_result.update(primitive)
        return literal_result

    if origin in (list, tuple, set, frozenset):
        item = args[0] if args else Any
        return {"type": "array", "items": _annotation_to_schema(item)}

    if origin is dict:
        value_t = args[1] if len(args) == 2 else Any
        value_schema = _annotation_to_schema(value_t)
        result = {"type": "object"}
        if value_schema:
            result["additionalProperties"] = value_schema
        return result

    if _is_union_origin(origin):
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
        return typing.get_type_hints(fn, include_extras=True)
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
