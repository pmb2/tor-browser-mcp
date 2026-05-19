"""Unit tests for per-session CA generation under ``proxy-intercept``."""

from __future__ import annotations

import hashlib
import re
import ssl
from pathlib import Path

import pytest

from torbrowser_driver._proxy_intercept_ca import generate_session_ca
from torbrowser_driver.exceptions import ProxyInterceptError

pytest.importorskip("mitmproxy")


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def test_generate_writes_non_empty_pem(tmp_path: Path) -> None:
    ca_dir = tmp_path / "ca"
    pem_path, fingerprint = generate_session_ca(ca_dir)
    assert pem_path.is_file()
    assert pem_path.parent == ca_dir
    assert pem_path.name == "mitmproxy-ca-cert.pem"
    assert pem_path.stat().st_size > 0
    assert "-----BEGIN CERTIFICATE-----" in pem_path.read_text("ascii")
    assert _HEX64.match(fingerprint), fingerprint


def test_fingerprint_matches_independent_sha256_of_der(tmp_path: Path) -> None:
    pem_path, fingerprint = generate_session_ca(tmp_path / "ca")
    pem_text = pem_path.read_text("ascii")
    der = ssl.PEM_cert_to_DER_cert(pem_text)
    expected = hashlib.sha256(der).hexdigest()
    assert fingerprint == expected


def test_idempotent_returns_same_fingerprint(tmp_path: Path) -> None:
    ca_dir = tmp_path / "ca"
    _, first = generate_session_ca(ca_dir)
    _, second = generate_session_ca(ca_dir)
    assert first == second


def test_distinct_dirs_produce_distinct_fingerprints(tmp_path: Path) -> None:
    _, fp_a = generate_session_ca(tmp_path / "a")
    _, fp_b = generate_session_ca(tmp_path / "b")
    assert fp_a != fp_b


def test_missing_pem_after_generation_raises(monkeypatch, tmp_path: Path) -> None:
    """If mitmproxy ever changes its output layout the helper raises cleanly."""

    from torbrowser_driver import _proxy_intercept_ca as mod

    class _NoopStore:
        @staticmethod
        def from_store(path, basename, key_size):
            # Do not create any files.
            return None

    monkeypatch.setattr(
        mod, "_certs", None, raising=False
    )  # ensure attribute write space exists
    # Patch the mitmproxy.certs symbol the helper imports lazily.
    import mitmproxy.certs as real_certs

    monkeypatch.setattr(real_certs, "CertStore", _NoopStore)

    with pytest.raises(ProxyInterceptError, match="expected CA cert"):
        generate_session_ca(tmp_path / "ca")
