"""Command-line argument parsing and :class:`DriverConfig` construction.

The CLI here is the only place :class:`DriverConfig` and
:class:`PathPolicy` are assembled from user-supplied strings. Higher-level
code (``__main__`` and tests) receives validated objects rather than raw
:class:`argparse.Namespace` values. Validation failures use
:data:`argparse.ArgumentParser.error`, which terminates the process with
``SystemExit(2)`` and a clear message.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import time
from pathlib import Path

from torbrowser_driver import (
    DEFAULT_CAPABILITIES,
    KNOWN_CAPABILITIES,
    OPTIONAL_CAPABILITIES,
    DriverConfig,
    PathPolicy,
)

from .server import ServerOptions, run_server

_LOG_LEVELS = ("debug", "info", "warning", "error")
_PROFILE_MODES = ("ephemeral", "persistent")
_TRANSPORTS = ("stdio",)

log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Return the argparse parser describing every CLI flag."""

    parser = argparse.ArgumentParser(
        prog="torbrowser-mcp",
        description=(
            "Run an MCP server that drives a stock Tor Browser bundle via "
            "geckodriver and Marionette."
        ),
    )
    parser.add_argument(
        "--tbb-root",
        type=Path,
        default=None,
        help=(
            "Path to an extracted Tor Browser bundle (the directory that "
            "contains 'Browser/'). Falls back to the TBB_ROOT environment "
            "variable when omitted."
        ),
    )
    parser.add_argument(
        "--geckodriver-path",
        type=Path,
        default=None,
        help=(
            "Path to a geckodriver binary compatible with the Firefox ESR "
            "version Tor Browser ships. Default: look up on PATH."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Directory for tool-produced files (screenshots, HARs, dumps). "
            "Created if it does not exist."
        ),
    )
    parser.add_argument(
        "--allowed-root",
        dest="allowed_roots",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Additional filesystem root that tools may read from. May be "
            "passed multiple times."
        ),
    )
    parser.add_argument(
        "--allow-unrestricted-file-access",
        action="store_true",
        help=(
            "Disable the filesystem path policy entirely. The MCP server "
            "will accept any local path the client supplies. Off by default."
        ),
    )
    parser.add_argument(
        "--caps",
        default="",
        help=(
            "Comma-separated optional capability groups to enable on top of "
            "the defaults. Valid choices: "
            f"{', '.join(sorted(OPTIONAL_CAPABILITIES))}."
        ),
    )
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Shorthand for adding 'unsafe' to --caps.",
    )
    parser.add_argument(
        "--tool-module",
        dest="tool_modules",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Trusted Python file exporting a register(context) function. May "
            "be passed multiple times. Loaded in the server process."
        ),
    )
    parser.add_argument(
        "--socks-port",
        type=int,
        default=9250,
        help="SOCKS port for the bundled tor we spawn (default 9250).",
    )
    parser.add_argument(
        "--control-port",
        type=int,
        default=9251,
        help="Tor control port for the bundled tor (default 9251).",
    )
    parser.add_argument(
        "--profile-mode",
        choices=_PROFILE_MODES,
        default="ephemeral",
        help=(
            "'ephemeral' (default) clones the bundle's profile.default into a "
            "session directory; 'persistent' reuses --profile-path directly."
        ),
    )
    parser.add_argument(
        "--profile-path",
        type=Path,
        default=None,
        help="Persistent profile directory. Required when --profile-mode=persistent.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run Tor Browser with -headless (off by default).",
    )
    parser.add_argument(
        "--max-restarts",
        type=int,
        default=10,
        help="Max automatic restarts on crash before giving up (default 10, 0=no restart).",
    )
    parser.add_argument(
        "--restart-delay",
        type=float,
        default=5.0,
        help="Delay in seconds before restarting after a crash (default 5).",
    )
    parser.add_argument(
        "--log-level",
        choices=_LOG_LEVELS,
        default="info",
        help="Root log level for the server process (default 'info').",
    )
    parser.add_argument(
        "--transport",
        choices=_TRANSPORTS,
        default="stdio",
        help="MCP transport. Only 'stdio' is supported today.",
    )
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse ``argv`` (or ``sys.argv[1:]``) and return the namespace."""

    parser = build_parser()
    return parser.parse_args(argv)


def _parse_caps(value: str, unsafe_flag: bool, parser: argparse.ArgumentParser) -> frozenset[str]:
    raw = [c.strip() for c in value.split(",") if c.strip()]
    if unsafe_flag:
        raw.append("unsafe")
    requested = set(raw)
    unknown = requested - KNOWN_CAPABILITIES
    if unknown:
        parser.error(
            "unknown capability(s): "
            f"{', '.join(sorted(unknown))}. "
            f"Optional capabilities are: {', '.join(sorted(OPTIONAL_CAPABILITIES))}."
        )
    not_optional = requested - OPTIONAL_CAPABILITIES
    if not_optional:
        parser.error(
            "the following capabilities are enabled by default and cannot be "
            "passed via --caps: "
            f"{', '.join(sorted(not_optional))}."
        )
    return frozenset(DEFAULT_CAPABILITIES | requested)


def config_from_args(
    ns: argparse.Namespace,
) -> tuple[DriverConfig, ServerOptions]:
    """Translate a parsed namespace into a :class:`DriverConfig` plus
    :class:`ServerOptions` pair. Validation errors raise
    :class:`SystemExit` via :meth:`argparse.ArgumentParser.error`.
    """

    parser = build_parser()

    tbb_root = ns.tbb_root
    if tbb_root is None:
        env_root = os.environ.get("TBB_ROOT")
        if not env_root:
            parser.error(
                "--tbb-root is required (or set the TBB_ROOT environment variable)."
            )
        tbb_root = Path(env_root)
    tbb_root = tbb_root.expanduser().resolve(strict=False)
    if not tbb_root.is_dir():
        parser.error(f"--tbb-root {tbb_root!s} is not a directory.")

    output_dir = ns.output_dir.expanduser().resolve(strict=False)
    output_dir.mkdir(parents=True, exist_ok=True)

    allowed_roots: list[Path] = []
    for root in ns.allowed_roots:
        resolved = Path(root).expanduser().resolve(strict=False)
        if not resolved.is_dir():
            parser.error(f"--allowed-root {resolved!s} is not a directory.")
        allowed_roots.append(resolved)

    if ns.profile_mode == "persistent" and ns.profile_path is None:
        parser.error("--profile-mode=persistent requires --profile-path.")

    enabled_caps = _parse_caps(ns.caps, ns.unsafe, parser)

    path_policy = PathPolicy.from_config(
        output_dir=output_dir,
        allowed_roots=allowed_roots,
        unrestricted=ns.allow_unrestricted_file_access,
    )

    profile_path = (
        ns.profile_path.expanduser().resolve(strict=False)
        if ns.profile_path is not None
        else None
    )
    geckodriver_path = (
        ns.geckodriver_path.expanduser().resolve(strict=False)
        if ns.geckodriver_path is not None
        else None
    )

    config = DriverConfig(
        tbb_root=tbb_root,
        path_policy=path_policy,
        geckodriver_path=geckodriver_path,
        profile_mode=ns.profile_mode,
        profile_path=profile_path,
        headless=ns.headless,
        socks_port=ns.socks_port,
        control_port=ns.control_port,
        enabled_caps=enabled_caps,
    )

    options = ServerOptions(
        tool_modules=tuple(Path(p).expanduser().resolve(strict=False) for p in ns.tool_modules),
        log_level=ns.log_level,
        transport=ns.transport,
    )

    return config, options


def main() -> None:
    """Parse the command line and run the MCP server with crash recovery.

    If the server crashes (browser crash, socket failure, etc.), it is
    automatically restarted up to ``--max-restarts`` times with an
    exponential backoff delay (starting at ``--restart-delay`` seconds,
    doubling each attempt, capped at 120s). Clean shutdowns (exit code 0)
    break the restart loop.
    """

    ns = parse_args()
    config, options = config_from_args(ns)
    logging.basicConfig(
        level=getattr(logging, options.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    max_restarts = ns.max_restarts
    restart_delay = ns.restart_delay
    attempt = 0

    while True:
        try:
            asyncio.run(run_server(config, options))
            log.info("Server shutdown cleanly.")
            return
        except Exception as exc:
            attempt += 1
            if max_restarts > 0 and attempt > max_restarts:
                log.error(
                    "Server crashed %d times (max %d). Giving up.",
                    attempt, max_restarts,
                )
                raise

            delay = min(restart_delay * (2 ** (attempt - 1)), 120.0)
            log.warning(
                "Server crashed (attempt %d/%d): %s. Restarting in %.1fs...",
                attempt, max_restarts, exc, delay,
            )
            time.sleep(delay)
