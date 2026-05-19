"""End-to-end MCP wire-path smoke test against a real Tor Browser.

Spawns ``python -m torbrowser_mcp`` as a subprocess, connects with the
``mcp`` SDK's stdio client, and round-trips ``initialize``, ``tools/list``
and a handful of ``tools/call`` invocations. The point of this test is
the stdio + JSON-RPC + tool-dispatch path; Tor routing semantics live in
``test_smoke_integration.py``.

Opt-in: skipped unless ``TBB_ROOT`` and ``GECKODRIVER_PATH`` are set. Run
with ``pytest -m integration``.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, TextContent

pytestmark = pytest.mark.integration

# Pinned to avoid colliding with test_smoke_integration.py which uses the
# defaults 9250/9251. Lets the two integration tests run back-to-back even
# if the bundled tor from the previous run is still tearing down.
SOCKS_PORT = 9252
CONTROL_PORT = 9253

# Watchdog around the whole client flow. Bootstrap of the bundled tor
# plus Firefox bringup is the dominant cost; the wire-path calls
# themselves are sub-second once the driver is up.
OVERALL_TIMEOUT_S = 240.0

EXPECTED_TOOL_NAMES = {
    "browser_navigate",
    "browser_title",
    "browser_current_url",
    "browser_take_screenshot",
    "tor_status",
    "tor_check_identity",
    "tor_new_identity",
    "browser_dump_page",
}


def _decode_text_payload(result: CallToolResult) -> Any:
    """Pull the first ``TextContent`` block off ``result`` and JSON-decode it.

    The server's ``_format_result`` wraps dict results as one JSON block
    plus optionally a second human-readable artifact-path block. We only
    care about the first.
    """

    assert result.content, "CallToolResult.content was empty"
    block = result.content[0]
    assert isinstance(block, TextContent), f"expected TextContent, got {type(block).__name__}"
    return json.loads(block.text)


async def _drive_session(
    tbb_root: Path,
    geckodriver_path: Path,
    output_dir: Path,
) -> None:
    args = [
        "-m",
        "torbrowser_mcp",
        "--tbb-root",
        str(tbb_root),
        "--geckodriver-path",
        str(geckodriver_path),
        "--output-dir",
        str(output_dir),
        "--socks-port",
        str(SOCKS_PORT),
        "--control-port",
        str(CONTROL_PORT),
        "--log-level",
        "info",
    ]

    # Pass the environment through so the subprocess sees TBB_ROOT et al.
    # if it needs them, and so PATH / SYSTEMROOT-style essentials are
    # carried into the child on Windows.
    env = dict(os.environ)

    params = StdioServerParameters(
        command=sys.executable,
        args=args,
        env=env,
    )

    async with stdio_client(params) as (read_stream, write_stream):  # noqa: SIM117
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            tool_names = {t.name for t in tools_result.tools}
            missing = EXPECTED_TOOL_NAMES - tool_names
            assert not missing, f"missing tools over the wire: {sorted(missing)}"

            for tool in tools_result.tools:
                schema = tool.inputSchema
                assert isinstance(schema, dict), f"{tool.name} has non-dict inputSchema"
                assert schema.get("type") == "object", (
                    f"{tool.name} inputSchema.type is {schema.get('type')!r}, want 'object'"
                )

            nav = await session.call_tool("browser_navigate", {"url": "about:blank"})
            assert not nav.isError, f"browser_navigate failed: {nav.content!r}"
            nav_payload = _decode_text_payload(nav)
            assert "url" in nav_payload, f"browser_navigate payload missing 'url': {nav_payload!r}"

            title = await session.call_tool("browser_title", {})
            assert not title.isError, f"browser_title failed: {title.content!r}"
            title_payload = _decode_text_payload(title)
            assert "title" in title_payload, (
                f"browser_title payload missing 'title': {title_payload!r}"
            )

            current = await session.call_tool("browser_current_url", {})
            assert not current.isError, f"browser_current_url failed: {current.content!r}"
            current_payload = _decode_text_payload(current)
            assert "url" in current_payload, (
                f"browser_current_url payload missing 'url': {current_payload!r}"
            )
            assert current_payload["url"].startswith("about:"), (
                f"browser_current_url after about:blank is {current_payload['url']!r}"
            )

            status = await session.call_tool("tor_status", {})
            assert not status.isError, f"tor_status failed: {status.content!r}"
            status_payload = _decode_text_payload(status)
            assert status_payload.get("running") is True, f"tor_status: {status_payload!r}"
            assert status_payload.get("circuit_established") is True, (
                f"tor_status reports no circuit: {status_payload!r}"
            )

            shot = await session.call_tool("browser_take_screenshot", {})
            assert not shot.isError, f"browser_take_screenshot failed: {shot.content!r}"
            shot_payload = _decode_text_payload(shot)
            assert "path" in shot_payload, f"screenshot result missing 'path': {shot_payload!r}"
            shot_path = Path(shot_payload["path"])
            assert shot_path.is_file(), f"screenshot path does not exist: {shot_path}"
            assert shot_path.stat().st_size > 0, f"screenshot file is empty: {shot_path}"
            # When the result carries a path, the server appends a second
            # informational block. Sanity-check that, but don't fail the
            # test if a future refactor drops it.
            if len(shot.content) >= 2:
                second = shot.content[1]
                assert isinstance(second, TextContent)
                assert str(shot_path) in second.text

            cfg = await session.call_tool("browser_get_config", {})
            assert not cfg.isError, f"browser_get_config failed: {cfg.content!r}"
            cfg_payload = _decode_text_payload(cfg)
            assert cfg_payload["socks_port"] == SOCKS_PORT, (
                f"config socks_port = {cfg_payload['socks_port']!r}, want {SOCKS_PORT}"
            )
            assert cfg_payload["control_port"] == CONTROL_PORT, (
                f"config control_port = {cfg_payload['control_port']!r}, want {CONTROL_PORT}"
            )
            assert Path(cfg_payload["output_dir"]) == output_dir.resolve(), (
                f"config output_dir = {cfg_payload['output_dir']!r}, want {output_dir.resolve()}"
            )
            assert "core" in cfg_payload["enabled_caps"], (
                f"enabled_caps missing 'core': {cfg_payload['enabled_caps']!r}"
            )
            assert "tor" in cfg_payload["enabled_caps"], (
                f"enabled_caps missing 'tor': {cfg_payload['enabled_caps']!r}"
            )

            broken = await session.call_tool("browser_navigate", {})
            assert broken.isError, (
                f"browser_navigate with no url should have errored, got {broken!r}"
            )

            # After the broken call the server must still be alive and
            # responsive on the same stdio session.
            tools_again = await session.list_tools()
            assert {t.name for t in tools_again.tools} == tool_names, (
                "tool surface changed after a bad call"
            )


def test_mcp_stdio_wire_path(
    tbb_root: Path, geckodriver_path: Path | None, tmp_path: Path
) -> None:
    if geckodriver_path is None:
        pytest.skip("GECKODRIVER_PATH not set")
    output_dir = tmp_path / "mcp-output"
    output_dir.mkdir(parents=True, exist_ok=True)

    async def _runner() -> None:
        try:
            await asyncio.wait_for(
                _drive_session(tbb_root, geckodriver_path, output_dir),
                timeout=OVERALL_TIMEOUT_S,
            )
        except asyncio.TimeoutError as exc:
            raise AssertionError(
                f"MCP stdio wire-path test exceeded {OVERALL_TIMEOUT_S:.0f}s; "
                "subprocess or client likely hung during initialize/list_tools/call_tool"
            ) from exc

    asyncio.run(_runner())
