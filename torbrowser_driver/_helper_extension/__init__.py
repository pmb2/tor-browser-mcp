"""On-disk source of the WebExtension installed by the helper bridge.

The Python package only exposes the directory path; the extension itself
is plain data (``manifest.json``, ``background.js``) copied into a
per-session location at install time. ``config.json`` is generated next
to the copied files and is therefore not shipped here.
"""

from __future__ import annotations

from pathlib import Path

HELPER_EXTENSION_DIR: Path = Path(__file__).parent

# The gecko id pinned in ``manifest.json``. Profile-scope sideload places the
# packed XPI at ``<profile>/extensions/<HELPER_EXTENSION_ID>.xpi``; Firefox
# discovers the addon by matching the filename stem against this id at
# profile-startup time.
HELPER_EXTENSION_ID: str = "helper@tor-browser-mcp.local"

__all__ = ["HELPER_EXTENSION_DIR", "HELPER_EXTENSION_ID"]
