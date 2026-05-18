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

## Helper extension capability

The `helper-extension` capability installs a per-session temporary MV2 WebExtension into Tor Browser and runs a localhost HTTP long-poll bridge between the driver and the extension's background page. It exposes nine tool methods covering bridge status, network observation, document-start init scripts, and declarative request routing.

### Why it is opt-in

The helper installs an unsigned MV2 extension via chrome-context Marionette and grants it `internal:privateBrowsingAllowed` so its background page runs under Tor Browser's permanent private browsing. This is not a stealth capability by design: pages and scripts inside the same Tor Browser session can in principle observe that a WebExtension is loaded. The capability also sets `extensions.webextensions.remote=false` so `webRequest` listeners run in the same process as the background page; this is a small additional fingerprint signal but is consistent with the cap's opt-in stance. Tor Browser's permanent private browsing isolation (cookies, storage, FPI) is preserved.

### Tool methods

| Tool | Purpose |
| --- | --- |
| `browser_extension_status` | Snapshot of install / bridge state and counts of active captures and registered init scripts. |
| `browser_network_capture_start` / `browser_network_capture_stop` | Observe requests matching WebExtension match patterns; returns per-request envelopes on stop. |
| `browser_add_init_script` / `browser_remove_init_script` | Register and unregister `document_start` content scripts across all frames. |
| `browser_route` / `browser_unroute` / `browser_route_list` | Install, remove, and inspect declarative routing rules (mock body, redirect URL, or header rewrite). |
| `browser_network_state_set` | Toggle a simulated offline mode that cancels new requests at `onBeforeRequest`. |

### Known limitations

- **Response body bytes do not arrive on TB 15.x.** `webRequest.filterResponseData`'s `ondata` callback does not deliver bytes on Tor Browser 15.0.13 / Firefox 140 ESR for the URL patterns the capture API targets. Capture envelopes (URL, method, status code, request and response headers, peer IP, error, timestamps) are fully populated; the `response_body` field is typically empty. For real body capture, enable the `proxy-intercept` capability instead.
- **Mock-mode routes do not deliver synthesised bodies on TB 15.x.** `browser_route(..., body=...)` works by returning a `data:` URL from `onBeforeRequest`. On TB 15.x the redirect itself fails to deliver the synthesised body to page-context `fetch()` for subresources; the call rejects with a network error. The route is registered and visible in `browser_route_list`, but the body never reaches the page. Redirect-mode (`redirect_url=...`) and header-rewrite mode work end-to-end. For full mocking with custom status codes or arbitrary response headers, use `proxy-intercept` (or wait for a Tor Browser build that restores `data:`-URL subresource redirects).
- **Offline mode does not abort in-flight requests.** `browser_network_state_set("offline")` cancels new requests at `onBeforeRequest`; requests already past that hook continue to completion. `navigator.onLine` is not toggled.
- **Manifest V2.** The capability relies on blocking `webRequest` and will need to be revisited if Tor Browser moves past MV2.

### Coexistence with `proxy-intercept`

When both capabilities are enabled they observe different layers and do not collide: the helper sees and routes requests at the browser layer, while `proxy-intercept` operates on the wire traffic that leaves the browser. A helper-mode mock that rewrites a request to a `data:` URL is invisible to the intercept proxy because the browser fulfils `data:` URLs locally.

## Filesystem policy

Tool calls that read or write files are resolved through a path policy: outputs land under `--output-dir`, and reads are restricted to MCP roots, the server cwd, and any `--allowed-root` directories. `--allow-unrestricted-file-access` disables the guardrail. This is a convenience boundary, not a sandbox.

## Layout

- `torbrowser_driver/` - launch recipe, capability registry, and capability-tagged driver primitives.
- `torbrowser_mcp/` - MCP server that walks the driver's capability registry and exposes each method as a tool.
- `tests/` - unit tests plus an opt-in integration smoke test (`pytest -m integration`).
