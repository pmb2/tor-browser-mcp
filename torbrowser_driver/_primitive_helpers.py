"""Shared helpers for the per-capability primitive modules.

These utilities back the ``limit`` / ``filename`` / inline-cap conventions
that every primitive module follows: validating ``limit`` arguments,
slicing lists against ``limit``, writing JSON payloads under the output
dir, and replacing oversized inline structured results with a truncation
summary so the MCP transport never has to ship multi-megabyte dicts.
"""

from __future__ import annotations

import json
from typing import Any

_STRUCTURED_INLINE_CAP = 524_288


def _validate_limit(limit: int | None) -> None:
    if limit is not None and (
        isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
    ):
        raise ValueError("limit must be a non-negative int or None")


def _limit_items(
    items: list[Any],
    limit: int | None,
) -> tuple[list[Any], bool]:
    _validate_limit(limit)
    if limit is None:
        return items, False
    return items[:limit], len(items) > limit


def _write_json_payload(
    path_policy: Any,
    filename: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    path = path_policy.resolve_output(filename)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    path.write_bytes(data)
    result: dict[str, Any] = {"path": str(path), "bytes": len(data)}
    for key in ("count", "total", "truncated", "size"):
        if key in payload:
            result[key] = payload[key]
    return result


def _bounded_inline_json(key: str, value: Any) -> dict[str, Any]:
    data = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
    if len(data) <= _STRUCTURED_INLINE_CAP:
        return {key: value}
    return {
        "truncated": True,
        "bytes": len(data),
        "inline_cap": _STRUCTURED_INLINE_CAP,
        "note": "structured result exceeds inline cap; rerun with filename",
    }
