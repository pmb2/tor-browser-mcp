"""Per-session CA generation for the ``proxy-intercept`` capability.

A fresh CA is materialised under ``<session_dir>/intercept-ca/`` every
time the driver starts. The CA dies with the session: regenerating
rather than persisting avoids the footgun of a stale CA lingering in
a system trust store, where any later process running the same
``tor-browser-mcp`` install could transparently MITM the user's
browser.

Generation is delegated to mitmproxy's ``CertStore.from_store`` helper,
which writes the cert store (``mitmproxy-ca-cert.pem`` plus its
sibling files) if missing and returns an in-memory ``CertStore``
either way. The PEM file is the one Firefox's ``Certificates.Install``
policy reads. The SHA-256 fingerprint of the DER encoding of the CA
certificate is returned alongside the path so the diagnostics layer
can let callers verify the cert they observe in peer chains matches
the one this driver installed.
"""

from __future__ import annotations

import hashlib
import ssl
from pathlib import Path

from .exceptions import ProxyInterceptError


_CA_BASENAME = "mitmproxy"
_CA_CERT_FILENAME = f"{_CA_BASENAME}-ca-cert.pem"
_CA_KEY_SIZE = 2048


def generate_session_ca(ca_dir: Path) -> tuple[Path, str]:
    """Generate (or reuse) a CA under ``ca_dir`` and return its metadata.

    Returns ``(ca_pem_path, fingerprint)`` where ``ca_pem_path`` is the
    PEM-encoded CA certificate Firefox's policy engine reads, and
    ``fingerprint`` is the lowercase SHA-256 hex digest of the DER
    encoding of that certificate (64 chars, no separators).

    Idempotent: a second call against the same ``ca_dir`` reuses the
    on-disk store and returns the same fingerprint.

    Raises :class:`ProxyInterceptError` if generation fails or the
    expected PEM file is not present after generation.
    """

    try:
        ca_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ProxyInterceptError(
            f"could not create CA directory {ca_dir!s}: {exc}"
        ) from exc

    try:
        from mitmproxy import certs as _certs
    except ImportError as exc:
        raise ProxyInterceptError(
            "mitmproxy is not installed; install the 'proxy-intercept' extra"
        ) from exc

    try:
        _certs.CertStore.from_store(str(ca_dir), _CA_BASENAME, _CA_KEY_SIZE)
    except Exception as exc:
        raise ProxyInterceptError(
            f"mitmproxy CA generation failed in {ca_dir!s}: {exc!r}"
        ) from exc

    ca_pem_path = ca_dir / _CA_CERT_FILENAME
    if not ca_pem_path.is_file():
        candidates = sorted(p.name for p in ca_dir.glob("*.pem"))
        raise ProxyInterceptError(
            f"expected CA cert at {ca_pem_path!s} after generation; "
            f"found PEM files: {candidates!r}"
        )

    fingerprint = _sha256_der_fingerprint(ca_pem_path)
    return ca_pem_path, fingerprint


def _sha256_der_fingerprint(ca_pem_path: Path) -> str:
    """Return the lowercase SHA-256 hex digest of the DER form of ``ca_pem_path``.

    The PEM file may contain multiple PEM blocks (mitmproxy embeds the
    CA cert plus its private key in ``mitmproxy-ca.pem``); for the
    cert-only file the first ``CERTIFICATE`` block is the CA.
    """

    pem_text = ca_pem_path.read_text(encoding="ascii", errors="strict")
    der = ssl.PEM_cert_to_DER_cert(_first_cert_block(pem_text))
    return hashlib.sha256(der).hexdigest()


def _first_cert_block(pem_text: str) -> str:
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    start = pem_text.find(begin)
    if start == -1:
        raise ProxyInterceptError("no CERTIFICATE block found in PEM file")
    stop = pem_text.find(end, start)
    if stop == -1:
        raise ProxyInterceptError("PEM CERTIFICATE block is not terminated")
    return pem_text[start : stop + len(end)] + "\n"
