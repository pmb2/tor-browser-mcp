"""Structural assertions over the helper extension's manifest.json."""

from __future__ import annotations

import json

from torbrowser_driver._helper_extension import HELPER_EXTENSION_DIR


def test_helper_extension_dir_exists() -> None:
    assert HELPER_EXTENSION_DIR.is_dir()
    assert (HELPER_EXTENSION_DIR / "manifest.json").is_file()
    assert (HELPER_EXTENSION_DIR / "background.js").is_file()
    assert (HELPER_EXTENSION_DIR / "background.html").is_file()


def test_manifest_is_mv2() -> None:
    manifest = json.loads(
        (HELPER_EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["manifest_version"] == 2


def test_manifest_lists_required_permissions() -> None:
    manifest = json.loads(
        (HELPER_EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8")
    )
    permissions = set(manifest["permissions"])
    required = {
        "webRequest",
        "webRequestBlocking",
        "<all_urls>",
        "tabs",
        "storage",
    }
    assert required.issubset(permissions)


def test_manifest_background_is_persistent_page() -> None:
    manifest = json.loads(
        (HELPER_EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8")
    )
    background = manifest["background"]
    # MV2 "scripts" is silently downgraded to event-page on Firefox 140
    # ESR (TB 15.x), which leaves the background page unloaded until an
    # event listener fires. Using "page" with an explicit HTML wrapper
    # keeps the page persistent and runs background.js at install time.
    assert background["page"] == "background.html"
    assert background["persistent"] is True


def test_manifest_has_pinned_gecko_id() -> None:
    manifest = json.loads(
        (HELPER_EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8")
    )
    gecko = manifest["browser_specific_settings"]["gecko"]
    assert gecko["id"] == "helper@tor-browser-mcp.local"


def test_manifest_has_no_content_scripts() -> None:
    manifest = json.loads(
        (HELPER_EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8")
    )
    assert "content_scripts" not in manifest
