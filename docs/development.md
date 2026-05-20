# Development guide

## Geckodriver

A compatible `geckodriver` binary is required to drive Tor Browser. The driver resolves which binary to use at session start, in this fixed order:

1. **`config.geckodriver_path` (or the `--geckodriver-path` CLI flag).** If you supplied a path, it is used verbatim and no other discovery happens. This is the air-gapped / offline path: nothing the resolver does can reach the network once you have set this.
2. **`shutil.which("geckodriver")`.** If a `geckodriver` binary is already on `PATH`, the driver uses it. This is the right answer when you maintain a system-wide install or have the bundle's geckodriver on `PATH`.
3. **On-first-run resolver.** If neither of the above produced a binary, the driver reads the bundle's `Browser/application.ini` to recover the Firefox ESR version Tor Browser is riding, maps that to a known-compatible `geckodriver` release via a static table, and downloads the release archive from <https://github.com/mozilla/geckodriver/releases> into a per-user cache. The cached binary is reused by every subsequent session.

The driver logs the URL it is about to fetch at `INFO` before issuing any HTTP request. Downloads only happen on a cache miss; a cache hit is silent and never reaches out.

### Version map

The static table maps Firefox ESR major to the matching `geckodriver` release. The newest matching entry wins; an unknown future Firefox major falls through to the most recent known pair, which is the closest compatible build at the time the table was last refreshed.

| Firefox ESR major | geckodriver |
| --- | --- |
| 140 (current Tor Browser 15.0.x) | 0.36.0 |
| 128 | 0.35.0 |
| 115 | 0.34.0 |
| 102 | 0.32.0 |
| 91 | 0.31.0 |
| 78 | 0.30.0 |

When Tor Browser moves to a newer Firefox ESR, add a new top entry to `_FIREFOX_ESR_TO_GECKODRIVER` in `torbrowser_driver/_geckodriver_resolver.py`. The table is ordered newest-first.

### Cache layout

The default cache directory is `~/.cache/tor-browser-mcp/geckodriver/`. Inside it, the resolver creates a version-keyed subdirectory:

```
~/.cache/tor-browser-mcp/geckodriver/
    0.36.0/
        geckodriver           (POSIX)
        geckodriver.exe       (Windows)
    0.35.0/
        geckodriver
```

Multiple Firefox ESR majors can coexist in the same cache; nothing is pruned automatically. To force a fresh download, delete the version subdirectory. To run completely offline, populate the directory from an out-of-band channel before the first session — the binary at the expected path is the only thing the resolver checks.

### Offline and air-gapped use

Two paths keep the resolver from touching the network:

- **Set `--geckodriver-path` (or `DriverConfig.geckodriver_path`).** The resolver is bypassed entirely; the supplied binary is used.
- **Pre-populate the cache directory.** Copy a compatible `geckodriver` binary into `~/.cache/tor-browser-mcp/geckodriver/<version>/geckodriver(.exe)` before the first session. The resolver finds the cache hit and never issues a request.

If neither path is set up and the network is unavailable on first run, the resolver raises a `BrowserLaunchError` describing the failure; no partial state is left in the cache directory.

### Deferred work

The current resolver does not perform checksum or signature verification beyond a size-sanity check on the downloaded archive (it must be between 256 KiB and 64 MiB). A hostile network can in principle substitute a different binary; users who need cryptographic guarantees should rely on `--geckodriver-path` and verify the binary themselves out of band. Checksum and SHA256SUMS verification is a candidate for a follow-up.

## Integration tests

The five live-browser integration smokes are opt-in. They are collected by the `integration` marker (`pyproject.toml` `[tool.pytest.ini_options]`) and skipped unconditionally unless `TBB_ROOT` is set in the environment. No test runs against a real Tor Browser in CI unless a runner image with a Tor Browser bundle is available — the current CI matrix does not provide one, so the unit suite is the mandatory gate and the live smokes remain a local developer responsibility.

### Environment variables

| Variable | Required for | Notes |
| --- | --- | --- |
| `TBB_ROOT` | all five smokes | Absolute path to the extracted Tor Browser bundle root (the directory that contains `Browser/`). Without this, every integration test is skipped. |
| `GECKODRIVER_PATH` | all five smokes | Absolute path to the geckodriver binary. Optional if geckodriver is already on `PATH`; set it when the bundled geckodriver inside the TB tree is not on `PATH`. |
| `TBB_ALLOW_DESTRUCTIVE_CAPS=1` | proxy-intercept smoke only | Enables the destructive-capabilities fixture. Without this, every test in `test_proxy_intercept_smoke_integration.py` is skipped. Required because that smoke installs a CA certificate into the live Tor Browser install directory via `policies.json`; teardown restores the prior state, but the side-effect is real enough that an explicit opt-in is required when running against a shared or valued TB installation. |

### Port allocation

Each smoke file claims a fixed SOCKS port, control port, and (where applicable) bridge or intercept port. Ports are hardcoded so the five smokes can run back-to-back without colliding on tor data dirs, control sockets, or marionette ports, even when a prior smoke's tor process is still in teardown.

| Smoke file | SOCKS | Control | Extra | Env gate |
| --- | --- | --- | --- | --- |
| `test_smoke_integration.py` | 9250 | 9251 | — | none |
| `test_mcp_smoke_integration.py` | 9252 | 9253 | — | none |
| `test_optional_caps_smoke_integration.py` | 9254 | 9255 | — | none |
| `test_helper_extension_smoke_integration.py` | 9256 | 9257 | bridge 9258, intercept 9259 | none |
| `test_proxy_intercept_smoke_integration.py` | 9259 | 9260 | intercept 9261 | `TBB_ALLOW_DESTRUCTIVE_CAPS=1` |

Note on port 9259: the helper-extension smoke uses 9259 as an `intercept_port` inside its fixture for mock-mode route fulfillment; the proxy-intercept smoke uses 9259 as its SOCKS port. There is no live overlap because the smokes run serially and the helper-extension fixture releases its TB session before the proxy-intercept smoke starts. This is one reason the smokes must be run in order and never in parallel.

Port allocation rule: when adding a new live-TB integration test file, claim the next free SOCKS/control pair after the highest currently-allocated port. The next free slot is 9262.

### Smoke separation: safe vs destructive

The first four smokes (driver-level, MCP wire, optional caps, helper-extension) are safe: they do not modify any file inside the Tor Browser install directory. They require only `TBB_ROOT` (and optionally `GECKODRIVER_PATH`) and can be run freely against any TB installation, including a shared one.

The proxy-intercept smoke (`test_proxy_intercept_smoke_integration.py`) is destructive: it writes a `policies.json` into the TB install directory to configure the embedded CA. Teardown restores the prior `policies.json` state (or removes it if it did not previously exist), but the mutation is real during the test run. That is why it is gated behind `TBB_ALLOW_DESTRUCTIVE_CAPS=1` in addition to `@pytest.mark.integration`.

### What each smoke verifies

**`test_smoke_integration.py`** (driver-level, ~37 s) — exercises the full driver lifecycle: boot, navigation, screenshot, `tor_status`, `tor_circuit_status`, `tor_check_identity`, `browser_extract_metadata`, `browser_dump_page`, NEWNYM exit-IP rotation (retried up to four times with `post_signal_sleep=12.0`), and teardown. This is the canonical sanity check for a new TB bundle or platform.

**`test_mcp_smoke_integration.py`** (MCP wire, ~24 s) — spawns `python -m torbrowser_mcp` as a subprocess and round-trips `initialize`, `tools/list`, six `tools/call` invocations, an error-path call, and a follow-up `tools/list` to confirm the server stayed alive. The point of this smoke is the stdio + JSON-RPC + tool-dispatch path, not Tor routing semantics.

**`test_optional_caps_smoke_integration.py`** (optional caps, ~25 s) — boots one shared TB session (module-scoped fixture) and exercises the vision, highlight, tor-routing, and unsafe capability mixins end-to-end, including chrome-scope JavaScript eval. Separate from the driver smoke because these capabilities are selectively enabled via `DEFAULT_CAPABILITIES` and each adds non-trivial setup.

**`test_helper_extension_smoke_integration.py`** (helper-extension cap, ~57 s) — installs the helper extension into a real TB session, verifies the WebSocket bridge handshake, fetch and XHR body capture with tor-exit assertion, `document_start` init-script injection, mock-route delivery via the bridge, route removal, and online/offline toggle. Also confirms the bridge port (9258) is released on teardown.

**`test_proxy_intercept_smoke_integration.py`** (proxy-intercept cap, ~135 s) — the most comprehensive smoke: CA + `policies.json` install, navigation and flow recording through the embedded mitmproxy listener, content-encoding decompression, host and status filters, save and reload via `mitmproxy.io.FlowReader`, replay with a modified User-Agent, and `policies.json` state restoration confirmed across consecutive sessions.

### Live CI strategy

Live-browser smokes are opt-in unless a stable runner image that ships a Tor Browser bundle is available. The unit suite (`pytest -m "not integration"`) is the mandatory CI gate and must stay fast (under two minutes total). Adding the live smokes to CI is the right long-term direction — it would catch regressions in the driver, MCP wire path, and platform-specific launch behavior — but only when a runner image provides a reproducible, versioned TB bundle. Until then, the `@pytest.mark.integration` guard and the `TBB_ROOT` runtime requirement are the boundary. When live CI is eventually enabled, the destructive proxy-intercept smoke (`TBB_ALLOW_DESTRUCTIVE_CAPS=1`) must run as a separate job so a `policies.json` mutation failure cannot block the safe-smoke job results.

### Run locally: cheat sheet

Replace the placeholder paths with the actual locations for your installation.

```bash
# Driver-level smoke (safe)
export TBB_ROOT=/path/to/tor-browser GECKODRIVER_PATH=/path/to/geckodriver
pytest -m integration tests/test_smoke_integration.py -v --tb=short

# MCP wire smoke (safe)
export TBB_ROOT=/path/to/tor-browser GECKODRIVER_PATH=/path/to/geckodriver
pytest -m integration tests/test_mcp_smoke_integration.py -v --tb=short

# Optional-caps smoke (safe)
export TBB_ROOT=/path/to/tor-browser GECKODRIVER_PATH=/path/to/geckodriver
pytest -m integration tests/test_optional_caps_smoke_integration.py -v --tb=short

# Helper-extension smoke (safe)
export TBB_ROOT=/path/to/tor-browser GECKODRIVER_PATH=/path/to/geckodriver
pytest -m integration tests/test_helper_extension_smoke_integration.py -v --tb=short

# Proxy-intercept smoke (destructive — writes policies.json into the TB install)
export TBB_ROOT=/path/to/tor-browser GECKODRIVER_PATH=/path/to/geckodriver TBB_ALLOW_DESTRUCTIVE_CAPS=1
pytest -m integration tests/test_proxy_intercept_smoke_integration.py -v --tb=short

# All four safe smokes in series
export TBB_ROOT=/path/to/tor-browser GECKODRIVER_PATH=/path/to/geckodriver
pytest -m integration \
    tests/test_smoke_integration.py \
    tests/test_mcp_smoke_integration.py \
    tests/test_optional_caps_smoke_integration.py \
    tests/test_helper_extension_smoke_integration.py \
    -v --tb=short
```

Do not run the five smokes in parallel; concurrent Tor Browser launches share tor data directories and control sockets in ways that produce non-deterministic failures.
