# tor-browser-mcp

A Model Context Protocol server that drives a stock Tor Browser via geckodriver + Marionette, with [`stem`](https://stem.torproject.org/) for Tor control. Lets MCP clients automate browsing inside Tor Browser while preserving its anonymity properties (RFP, letterboxing, FPI, font/WebGL restrictions).

No browser fork. No Firefox patch maintenance. No Playwright dependency.

## Status

Early development. Not yet usable. Design and tool surface are still being validated against current Tor Browser releases.
