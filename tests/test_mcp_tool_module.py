"""Tests for the ``--tool-module`` loader."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from torbrowser_driver import DriverConfig, DriverConfigError, PathPolicy
from torbrowser_mcp.tool_module import ToolContext, load_tool_module


@pytest.fixture()
def context(
    tmp_path: Path, fake_tbb_layout: Path
) -> tuple[ToolContext, list[tuple[str, object]]]:
    policy = PathPolicy.from_config(output_dir=tmp_path / "out", cwd=tmp_path)
    config = DriverConfig(tbb_root=fake_tbb_layout, path_policy=policy)

    calls: list[tuple[str, object]] = []

    def add_tool(name, fn, description=None, schema=None) -> None:
        calls.append((name, fn))

    ctx = ToolContext(
        driver=MagicMock(),
        config=config,
        path_policy=policy,
        output_dir=policy.output_dir,
        add_tool=add_tool,
    )
    return ctx, calls


def test_register_adds_tool(tmp_path: Path, context) -> None:
    ctx, calls = context
    mod = tmp_path / "ext.py"
    mod.write_text(
        "def register(ctx):\n"
        "    ctx.add_tool('hello', lambda: {'ok': True}, 'say hello')\n",
        encoding="utf-8",
    )
    added = load_tool_module(mod, ctx)
    assert added == ["hello"]
    assert calls[0][0] == "hello"


def test_missing_register_raises(tmp_path: Path, context) -> None:
    ctx, _ = context
    mod = tmp_path / "bad.py"
    mod.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(DriverConfigError):
        load_tool_module(mod, ctx)


def test_missing_file_raises(tmp_path: Path, context) -> None:
    ctx, _ = context
    with pytest.raises(DriverConfigError):
        load_tool_module(tmp_path / "no-such.py", ctx)


def test_import_failure_wrapped(tmp_path: Path, context) -> None:
    ctx, _ = context
    mod = tmp_path / "broken.py"
    mod.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    with pytest.raises(DriverConfigError):
        load_tool_module(mod, ctx)
