# tor-browser-mcp

A Model Context Protocol server that drives a stock Tor Browser via geckodriver + Marionette, with [`stem`](https://stem.torproject.org/) for Tor control. Lets MCP clients automate browsing inside Tor Browser while preserving its anonymity properties (RFP, letterboxing, FPI, font/WebGL restrictions).

No browser fork. No Firefox patch maintenance. No Playwright dependency.

## Status

Phase 3 close-out. The driver substrate, the default-capability MCP server, and all eight optional capabilities are implemented and exercised by per-capability unit tests plus live integration smokes against Tor Browser 15.0.13.

Optional capabilities, all opt-in: `vision`, `highlight`, `tor-routing`, `unsafe`, `pdf`, `http-over-tor`, `helper-extension`, `proxy-intercept`.

Integration coverage is Windows-validated. Linux is supported by the code but the integration smokes have not been run on it yet. macOS is out of scope.

## Limitations

- **Automation is detectable.** Default WebDriver mode leaves `navigator.webdriver === true`; pages and scripts inside the session can see they are being driven.
- **Not a stealth tool.** TLS client fingerprint, ALPN settings, and the proxy negotiation pattern distinguish a driven session from default Tor Browser use even before any capability adds further signals.
- **Not a Playwright drop-in.** No async/await on every call, no auto-waiting beyond the explicit `browser_wait_for_*` primitives, no built-in trace viewer.
- **The filesystem policy is a guardrail, not a sandbox.** It stops accidental writes outside the configured `output_dir`; it does not contain a malicious actor with shell access to the server process.
- **Linux integration coverage is pending.** The unit suite passes on Linux but the live-browser smokes have only been run on Windows so far.
- **macOS is out of scope.**

## Install

Requires Python 3.10+ and an extracted Tor Browser bundle. The `proxy-intercept` extra additionally requires Python 3.12+ because of mitmproxy 11's runtime floor.

From a checkout:

```bash
pip install -e .
```

Once published to PyPI:

```bash
pip install torbrowser-mcp
pip install torbrowser-mcp[proxy-intercept]
```

The package is not yet on PyPI; the lines above are forward-looking.

A compatible `geckodriver` is required. Tor Browser ships one on Linux x86_64 (under `Browser/`); on Windows, download the version matching Tor Browser's Firefox ESR from <https://github.com/mozilla/geckodriver/releases> (TB 15.0.x ships Firefox 140.10.2esr, which works with geckodriver v0.36.0).

## Run

```bash
torbrowser-mcp \
    --tbb-root /path/to/tor-browser \
    --output-dir ./torbrowser-mcp-output
```

`--tbb-root` may also come from the `TBB_ROOT` environment variable. Run `torbrowser-mcp --help` for the full flag set, including `--caps`, `--allowed-root`, `--profile-mode`, `--tool-module`, and `--unsafe`.

The server speaks MCP over stdio. A minimal `claude_desktop_config.json` entry:

```json
{
  "mcpServers": {
    "torbrowser": {
      "command": "torbrowser-mcp",
      "args": [
        "--tbb-root", "C:\\path\\to\\Tor Browser",
        "--output-dir", "C:\\path\\to\\outputs"
      ]
    }
  }
}
```

Any stdio MCP client (Claude Desktop, an SDK script, a custom harness) attaches the same way.

## Capabilities

Default-enabled (no flag): `core`, `state`, `extract`, `diagnostics`, `tor`, `network-observe`.

Opt-in via `--caps a,b,c`: `vision`, `pdf`, `highlight`, `http-over-tor`, `tor-routing`, `helper-extension`, `proxy-intercept`. `--unsafe` adds the trusted-local `unsafe` capability (see below).

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

- **Response body capture is JS-initiated only.** Bodies for `fetch` and `XMLHttpRequest` calls made from page JavaScript are captured via a page-world override the helper extension injects at `document_start`; matched entries surface with `source: "merged"` (webRequest envelope plus page-world body) or `source: "page"` (page-only request, no webRequest counterpart). Subresources initiated by the document parser - `<img>` `src`, `<link>` `href`, `<script>` `src`, top-level navigations - are still captured by `webRequest` for envelope metadata (URL, method, status, headers, peer IP, timing) but their bytes never reach the page-world override, so `response_body` stays empty on those entries. The underlying gap is that `webRequest.filterResponseData`'s `ondata` callback fires `onstop` without delivering payload bytes on Tor Browser 15.0.13 / Firefox 140 ESR. For unconditional wire-level body capture regardless of how the request was initiated, enable `proxy-intercept`.
- **Mock-mode responses are served from a localhost bridge, not through tor.** `browser_route(..., body=...)` registers the supplied body, status, and headers on the driver-side HTTP bridge under an unguessable `/mock/<uuid>` path and instructs the extension to redirect matching requests there. The page sees the full HTTP envelope -- arbitrary status code, arbitrary response headers, the registered body. Mock traffic never crosses tor and never reaches `proxy-intercept`'s flow buffer because the redirect target sits on the same loopback the bridge listens on. `proxy-intercept` is only needed to mock traffic the helper extension cannot see in the first place: document-parser-initiated subresources and WebSocket frame payloads. The bridge auto-fills permissive CORS headers (`Access-Control-Allow-Origin: *`, `Access-Control-Expose-Headers: *`) when callers do not supply their own so cross-origin fetches resolve.
- **Offline mode does not abort in-flight requests.** `browser_network_state_set("offline")` cancels new requests at `onBeforeRequest`; requests already past that hook continue to completion. `navigator.onLine` is not toggled.
- **Manifest V2.** The capability relies on blocking `webRequest` and will need to be revisited if Tor Browser moves past MV2.

### Coexistence with `proxy-intercept`

When both capabilities are enabled they observe different layers and do not collide: the helper sees and routes requests at the browser layer, while `proxy-intercept` operates on the wire traffic that leaves the browser. A helper-mode mock is invisible to the intercept proxy because the redirect target is the driver-side localhost bridge's `/mock/<uuid>` endpoint, which serves the synthesised response over loopback without ever crossing tor.

## Proxy intercept capability

The `proxy-intercept` capability boots an embedded mitmproxy on a daemon thread chained out through the bundled tor's SOCKS port, installs a per-session MITM CA into the Tor Browser install via `policies.json`, and reconfigures Firefox to use the intercept proxy as its HTTP(S) upstream. Decrypted request and response bodies for HTTP/1.1, HTTP/2, and WebSocket traffic land in a bounded in-memory buffer that the six observation tools listed below read against.

### Why it is opt-in

Enabling this capability changes what Tor Browser looks like on the wire and disables one of its anonymity properties:

- **Tor Browser's per-first-party circuit isolation is disabled** for the session: every flow is multiplexed through the same upstream proxy connection before being demultiplexed by mitmproxy onto tor circuits, so first-party isolation no longer holds.
- **The local intercept proxy sees every page's plaintext.** Decrypted bodies live in memory in the driver process and are written to disk verbatim when `browser_intercept_save` is called.
- **A per-session MITM CA is installed into the Tor Browser install directory.** The driver writes (or deep-merges into) `<tbb_root>/Browser/distribution/policies.json` and restores the prior state on teardown. This is destructive in the sense that it mutates the on-disk Tor Browser bundle for the lifetime of the session.
- **The session is trivially distinguishable from default Tor Browser** via TLS client fingerprint, ALPN/HTTP-2 settings, and the proxy negotiation pattern. This is not a stealth mode; use it for adversary emulation, detection engineering, and protocol reversing against content you control or are authorised to inspect.
- **Python 3.12+ is required for the optional extra.** `pip install torbrowser-mcp[proxy-intercept]` pulls in `mitmproxy>=11,<13`, which transitively requires `mitmproxy-rs>=0.12`. That wheel ships only `cp312-abi3` builds (Windows x86_64, manylinux x86_64, manylinux aarch64, macOS universal2). The core install stays at Python 3.10+; only this capability raises the floor.

When the cap is in the enabled set, the MCP server emits the warning above (verbatim) to stderr at `build_server` time so a misconfigured deployment cannot accidentally start the server without the user seeing the trade-off.

### Tool methods

| Tool | Purpose |
| --- | --- |
| `browser_intercept_start` | Confirms the substrate is running and returns the recorder's monotonic cursor plus the CA fingerprint (SHA-256 of the DER) so callers can tail new flows. |
| `browser_intercept_stop` | Clears the recorder buffer and resets the cursor; the daemon thread and proxy stay running for the rest of the session. |
| `browser_intercept_flows` | Lists captured flows with optional `since`, `host`, and `status_code` filters, a result `limit`, and optional inlined bodies capped at `max_body_bytes`. |
| `browser_intercept_flow` | Returns one captured flow by its mitmproxy-assigned id, with bodies inlined by default. |
| `browser_intercept_save` | Persists the current buffer as a native mitmproxy flow archive under the configured output directory. |
| `browser_intercept_replay` | Deep-copies a captured flow, applies optional request modifications (method, URL, headers, body, HTTP version), and replays it through the live intercept proxy; the replay surfaces as a new entry in the recorder buffer. |

### Known limitations

- **HTTP/3 / QUIC is not intercepted.** mitmproxy's classic interception path covers HTTP/1.1 and HTTP/2. Firefox normally falls back to HTTP/2 against an HTTP-proxy upstream; if a destination ends up speaking HTTP/3 anyway, the resulting traffic is invisible to the recorder.
- **HSTS-preloaded hosts cannot be MITM'd.** Firefox enforces the HSTS preload list independent of policy-installed CAs, so cert errors on preloaded hosts (Google properties, GitHub, Cloudflare, the social-network majors, etc.) are non-overridable. The capability records these as synthetic error flows; bodies are not available.
- **No flow persistence across sessions.** `browser_intercept_save` writes an archive, but a fresh session cannot replay or re-load it through the tool surface in this slice.

### Coexistence with `helper-extension`

Both capabilities can be enabled together; the helper observes and routes at the browser layer, the intercept proxy operates on wire traffic, so neither hides flows from the other except for helper-mode mock routes, which redirect to the driver-side localhost bridge's `/mock/<uuid>` endpoint and are served over loopback without crossing tor.

## Unsafe capability

The `unsafe` capability is an opt-in escape hatch for trusted local research workflows. It is enabled via `--unsafe` (or by adding `unsafe` to `--caps`) and adds three RCE-equivalent tools:

| Tool | What it exposes |
| --- | --- |
| `browser_chrome_evaluate_unsafe` | Runs arbitrary JavaScript in the Firefox **chrome** (browser-UI) context via Marionette. Chrome-context scripts can read arbitrary preferences, drive the browser UI, and reach into XPCOM. |
| `browser_run_python_unsafe` | `exec`s arbitrary Python in the running MCP server process, with the driver, the Selenium handle, the stem controller, and the path policy bound as globals. Stdout is captured into the response. |
| `tor_control_command_unsafe` | Sends a raw control command to the bundled tor, bypassing the `tor_get_info` allowlist. Accepts any verb the controller will honour, including `SETCONF`, `SIGNAL HALT`, and `EXTENDCIRCUIT` variants that can crash or partition tor. |

Each of these is RCE-equivalent in its respective layer: page-trust, host-trust, and tor-trust all collapse to "whatever the MCP client asks for, the server does." Never expose the `unsafe` capability to an untrusted MCP client. It exists so a researcher driving the server locally can poke at the chrome context, prototype a new primitive without restarting the server, or experiment with tor control verbs that the curated surface deliberately omits.

## Filesystem policy

Tool calls that read or write files are resolved through a path policy: outputs land under `--output-dir`, and reads are restricted to MCP roots, the server cwd, and any `--allowed-root` directories. `--allow-unrestricted-file-access` disables the guardrail. This is a convenience boundary, not a sandbox.

## Layout

- `torbrowser_driver/` - launch recipe, capability registry, and capability-tagged driver primitives.
- `torbrowser_mcp/` - MCP server that walks the driver's capability registry and exposes each method as a tool.
- `tests/` - unit tests plus an opt-in integration smoke suite (`pytest -m integration`); contributor install is `pip install -e .[dev]`.
