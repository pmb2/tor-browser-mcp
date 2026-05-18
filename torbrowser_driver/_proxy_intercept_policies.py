"""Install/restore ``policies.json`` under the Tor Browser install dir.

Firefox ESR (which Tor Browser tracks) reads enterprise-policy JSON
from ``<install-dir>/distribution/policies.json``. The ``Certificates``
policy with an ``Install`` list is the user-mode entry-point for
adding a trust anchor without touching NSS's ``cert9.db`` directly.

The path is the install dir, not the profile dir. Firefox's policy
engine ignores ``distribution/policies.json`` placed inside a profile.

This module:

* Writes a deep-merged ``policies.json`` so any other policy block a
  future bundle ships is preserved, and any existing
  ``Certificates.Install`` list keeps its prior entries.
* Snapshots the prior file (or writes a "no prior file" marker) into a
  caller-supplied snapshot directory so teardown can restore the
  pre-install state byte-equivalently.
* Pre-flights writability: a read-only install dir surfaces a clean
  :class:`ProxyInterceptError` at start rather than a half-finished
  write later.

Concurrency: ``policies.json`` is shared across every Tor Browser
instance using the same install. The driver does not lock it. Callers
running multiple sessions against the same install must serialise them
externally.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from .exceptions import ProxyInterceptError


log = logging.getLogger(__name__)


_SNAPSHOT_FILENAME = "policies.json.bak"
_NO_PRIOR_MARKER = "no-prior-policies.flag"
_STALE_MARKER_SUFFIX = ".tor-browser-mcp-stale-policy"


def policies_path(tbb_root: Path) -> Path:
    """Return the absolute path of the policies file under ``tbb_root``."""

    return tbb_root / "Browser" / "distribution" / "policies.json"


def install_certificate_policy(
    tbb_root: Path,
    ca_pem_path: Path,
    snapshot_dir: Path,
) -> Path:
    """Install ``ca_pem_path`` into the install-dir policies file.

    On entry, the prior policies file (if any) is snapshotted into
    ``snapshot_dir`` so :func:`restore_certificate_policy` can return
    the install dir to its pre-call state. The merge preserves any
    sibling policy blocks and any existing entries in
    ``Certificates.Install``; ``ca_pem_path`` is appended only if not
    already listed.

    Returns the absolute path of the written ``policies.json``.

    Raises :class:`ProxyInterceptError` when:

    * the ``distribution/`` directory cannot be created or written;
    * the existing ``policies.json`` is malformed JSON;
    * the snapshot cannot be written.
    """

    target = policies_path(tbb_root)
    dist_dir = target.parent

    try:
        dist_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ProxyInterceptError(
            f"policies.json install path not writable: {dist_dir!s} "
            f"({exc}); the Tor Browser install directory must be "
            f"writable, which usually means installing TB under a "
            f"user-owned location rather than a system path"
        ) from exc

    _assert_writable(dist_dir)

    snapshot_dir.mkdir(parents=True, exist_ok=True)
    snapshot_target = snapshot_dir / _SNAPSHOT_FILENAME
    marker_target = snapshot_dir / _NO_PRIOR_MARKER

    if target.is_file():
        prior_bytes = target.read_bytes()
        snapshot_target.write_bytes(prior_bytes)
        if marker_target.exists():
            marker_target.unlink()
        try:
            existing = json.loads(prior_bytes.decode("utf-8")) if prior_bytes else {}
        except json.JSONDecodeError as exc:
            raise ProxyInterceptError(
                f"existing policies.json at {target!s} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(existing, dict):
            raise ProxyInterceptError(
                f"existing policies.json at {target!s} is not a JSON object"
            )
    else:
        marker_target.write_text("", encoding="ascii")
        if snapshot_target.exists():
            snapshot_target.unlink()
        existing = {}

    merged = _deep_merge_certificate_install(existing, ca_pem_path)
    _atomic_write_json(target, merged)
    return target


def restore_certificate_policy(tbb_root: Path, snapshot_dir: Path) -> None:
    """Restore ``policies.json`` to its pre-install state.

    Reads the snapshot or marker file from ``snapshot_dir`` and either
    rewrites the prior content or deletes the file. Errors are logged
    at ERROR level and never raised: teardown must not mask a user
    exception. If neither snapshot nor marker exists, a warning is
    logged and a sibling ``.tor-browser-mcp-stale-policy`` marker is
    written next to the leftover file so a future driver launch can
    warn about it.
    """

    target = policies_path(tbb_root)
    snapshot_target = snapshot_dir / _SNAPSHOT_FILENAME
    marker_target = snapshot_dir / _NO_PRIOR_MARKER

    try:
        if snapshot_target.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(snapshot_target.read_bytes())
            snapshot_target.unlink()
            if marker_target.exists():
                marker_target.unlink()
            return

        if marker_target.is_file():
            if target.is_file():
                target.unlink()
            marker_target.unlink()
            return

        log.warning(
            "policies.json restore: no snapshot or marker in %s; "
            "leaving %s in place and writing stale-policy marker",
            snapshot_dir,
            target,
        )
        if target.is_file():
            stale_marker = target.with_suffix(target.suffix + _STALE_MARKER_SUFFIX)
            try:
                stale_marker.write_text("", encoding="ascii")
            except OSError:
                log.exception("could not write stale-policy marker at %s", stale_marker)
    except Exception:
        log.exception("policies.json restore failed for %s", target)


def _assert_writable(dist_dir: Path) -> None:
    """Touch a probe file in ``dist_dir``; raise on failure."""

    try:
        fd, name = tempfile.mkstemp(
            prefix=".tor-browser-mcp-writable-",
            dir=str(dist_dir),
        )
    except OSError as exc:
        raise ProxyInterceptError(
            f"policies.json install path not writable: {dist_dir!s} "
            f"({exc}); the Tor Browser install directory must be "
            f"writable, which usually means installing TB under a "
            f"user-owned location rather than a system path"
        ) from exc
    os.close(fd)
    try:
        os.unlink(name)
    except OSError:
        pass


def _deep_merge_certificate_install(
    existing: dict[str, Any], ca_pem_path: Path
) -> dict[str, Any]:
    """Return a copy of ``existing`` with our CA path merged into ``Certificates.Install``.

    Preserves every other top-level key and every other key under
    ``policies``. ``Certificates.ImportEnterpriseRoots`` is left alone
    when present; otherwise it is set to ``False`` so we do not
    silently enable a setting the user did not ask for.
    """

    merged = json.loads(json.dumps(existing)) if existing else {}
    policies = merged.setdefault("policies", {})
    if not isinstance(policies, dict):
        raise ProxyInterceptError(
            "existing policies.json has a non-object 'policies' value; refusing to merge"
        )
    certs = policies.setdefault("Certificates", {})
    if not isinstance(certs, dict):
        raise ProxyInterceptError(
            "existing policies.json has a non-object 'policies.Certificates' value; "
            "refusing to merge"
        )
    install = certs.setdefault("Install", [])
    if not isinstance(install, list):
        raise ProxyInterceptError(
            "existing policies.json has a non-list 'policies.Certificates.Install'; "
            "refusing to merge"
        )
    pem_str = str(ca_pem_path)
    if pem_str not in install:
        install.append(pem_str)
    certs.setdefault("ImportEnterpriseRoots", False)
    return merged


def _atomic_write_json(target: Path, content: dict[str, Any]) -> None:
    """Write ``content`` to ``target`` via a temp-file + rename."""

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".policies-",
        suffix=".json.tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(content, fp, indent=2, sort_keys=True)
            fp.write("\n")
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
