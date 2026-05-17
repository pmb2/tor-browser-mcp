# tor-browser-mcp

A Model Context Protocol server that drives a stock Tor Browser via geckodriver + Marionette, with [`stem`](https://stem.torproject.org/) for Tor control. Lets MCP clients automate browsing inside Tor Browser while preserving its anonymity properties (RFP, letterboxing, FPI, font/WebGL restrictions).

No browser fork. No Firefox patch maintenance. No Playwright dependency.

## Status

Early. The driver substrate and a default-capability MCP server are implemented and pass an integration smoke test against Tor Browser 15.0.13 on Windows. macOS is out of scope for now; Linux is supported by the code but has not been smoke-tested yet.

## Install

Requires Python 3.10+ and an extracted Tor Browser bundle.

```bash
pip install -e .[dev]
```

A compatible `geckodriver` is required. Tor Browser ships one on Linux x86_64 (under `Browser/`); on Windows, download the version matching Tor Browser's Firefox ESR from <https://github.com/mozilla/geckodriver/releases> (TB 15.0.x ships Firefox 140.10.2esr, which works with geckodriver v0.36.0).

## Run

```bash
torbrowser-mcp \
    --tbb-root /path/to/tor-browser \
    --output-dir ./torbrowser-mcp-output
```

`--tbb-root` may also come from the `TBB_ROOT` environment variable. Run `torbrowser-mcp --help` for the full flag set, including `--caps`, `--allowed-root`, `--profile-mode`, `--tool-module`, and `--unsafe`.

The server speaks MCP over stdio. Point an MCP client (Claude Desktop, an SDK script, or any stdio client) at the command above.

## Capabilities

Default-enabled (no flag): `core`, `state`, `extract`, `diagnostics`, `tor`, `network-observe`.

Opt-in via `--caps a,b,c`: `vision`, `pdf`, `highlight`, `http-over-tor`, `tor-routing`, `helper-extension`, `proxy-intercept`. `--unsafe` adds the trusted-local `unsafe` capability.

The default surface intentionally does not include stealth or anti-detection tooling; pages should expect to observe `navigator.webdriver === true` in default WebDriver mode.

## Filesystem policy

Tool calls that read or write files are resolved through a path policy: outputs land under `--output-dir`, and reads are restricted to MCP roots, the server cwd, and any `--allowed-root` directories. `--allow-unrestricted-file-access` disables the guardrail. This is a convenience boundary, not a sandbox.

## Layout

- `torbrowser_driver/` - launch recipe, capability registry, and capability-tagged driver primitives.
- `torbrowser_mcp/` - MCP server that walks the driver's capability registry and exposes each method as a tool.
- `tests/` - unit tests plus an opt-in integration smoke test (`pytest -m integration`).
