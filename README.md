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

## Proxy intercept capability

The `proxy-intercept` capability boots an embedded mitmproxy on a daemon thread chained out through the bundled tor's SOCKS port, installs a per-session MITM CA into the Tor Browser install via `policies.json`, and reconfigures Firefox to use the intercept proxy as its HTTP(S) upstream. Decrypted request and response bodies for HTTP/1.1, HTTP/2, and WebSocket traffic land in a bounded in-memory buffer that the five observation tools listed below read against.

### Why it is opt-in

Enabling this capability changes what Tor Browser looks like on the wire and disables one of its anonymity properties:

- **Tor Browser's per-first-party circuit isolation is disabled** for the session: every flow is multiplexed through the same upstream proxy connection before being demultiplexed by mitmproxy onto tor circuits, so first-party isolation no longer holds.
- **The local intercept proxy sees every page's plaintext.** Decrypted bodies live in memory in the driver process and are written to disk verbatim when `browser_intercept_save` is called.
- **A per-session MITM CA is installed into the Tor Browser install directory.** The driver writes (or deep-merges into) `<tbb_root>/Browser/distribution/policies.json` and restores the prior state on teardown. This is destructive in the sense that it mutates the on-disk Tor Browser bundle for the lifetime of the session.
- **The session is trivially distinguishable from default Tor Browser** via TLS client fingerprint, ALPN/HTTP-2 settings, and the proxy negotiation pattern. This is not a stealth mode; use it for adversary emulation, detection engineering, and protocol reversing against content you control or are authorised to inspect.
- **Python 3.12+ is required for the optional extra.** `pip install tor-browser-mcp[proxy-intercept]` pulls in `mitmproxy>=11,<13`, which transitively requires `mitmproxy-rs>=0.12`. That wheel ships only `cp312-abi3` builds (Windows x86_64, manylinux x86_64, manylinux aarch64, macOS universal2). The core install stays at Python 3.10+; only this capability raises the floor.

When the cap is in the enabled set, the MCP server emits the warning above (verbatim) to stderr at `build_server` time so a misconfigured deployment cannot accidentally start the server without the user seeing the trade-off.

### Tool methods

| Tool | Purpose |
| --- | --- |
| `browser_intercept_start` | Confirms the substrate is running and returns the recorder's monotonic cursor plus the CA fingerprint (SHA-256 of the DER) so callers can tail new flows. |
| `browser_intercept_stop` | Clears the recorder buffer and resets the cursor; the daemon thread and proxy stay running for the rest of the session. |
| `browser_intercept_flows` | Lists captured flows with optional `since`, `host`, and `status_code` filters, a result `limit`, and optional inlined bodies capped at `max_body_bytes`. |
| `browser_intercept_flow` | Returns one captured flow by its mitmproxy-assigned id, with bodies inlined by default. |
| `browser_intercept_save` | Persists the current buffer as a native mitmproxy flow archive under the configured output directory. |

`browser_intercept_replay` lands in a future slice; replay-on-the-wire is not in this surface yet.

### Known limitations

- **HTTP/3 / QUIC is not intercepted.** mitmproxy's classic interception path covers HTTP/1.1 and HTTP/2. Firefox normally falls back to HTTP/2 against an HTTP-proxy upstream; if a destination ends up speaking HTTP/3 anyway, the resulting traffic is invisible to the recorder.
- **HSTS-preloaded hosts cannot be MITM'd.** Firefox enforces the HSTS preload list independent of policy-installed CAs, so cert errors on preloaded hosts (Google properties, GitHub, Cloudflare, the social-network majors, etc.) are non-overridable. The capability records these as synthetic error flows; bodies are not available.
- **No flow persistence across sessions.** `browser_intercept_save` writes an archive, but a fresh session cannot replay or re-load it through the tool surface in this slice.

### Coexistence with `helper-extension`

Both capabilities can be enabled together; the helper observes and routes at the browser layer, the intercept proxy operates on wire traffic, so neither hides flows from the other except for helper-mode mock routes that resolve to a `data:` URL (those never leave Firefox and stay invisible to the intercept proxy).

## Filesystem policy

Tool calls that read or write files are resolved through a path policy: outputs land under `--output-dir`, and reads are restricted to MCP roots, the server cwd, and any `--allowed-root` directories. `--allow-unrestricted-file-access` disables the guardrail. This is a convenience boundary, not a sandbox.

## Layout

- `torbrowser_driver/` - launch recipe, capability registry, and capability-tagged driver primitives.
- `torbrowser_mcp/` - MCP server that walks the driver's capability registry and exposes each method as a tool.
- `tests/` - unit tests plus an opt-in integration smoke test (`pytest -m integration`).
