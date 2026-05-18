"""Unit tests for ``_proxy_intercept_policies`` install/restore."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from torbrowser_driver._proxy_intercept_policies import (
    install_certificate_policy,
    policies_path,
    restore_certificate_policy,
)
from torbrowser_driver.exceptions import ProxyInterceptError


def _make_tbb(tmp_path: Path) -> Path:
    root = tmp_path / "tbb"
    (root / "Browser" / "distribution").mkdir(parents=True)
    return root


def _make_ca(tmp_path: Path, name: str = "ca.pem") -> Path:
    p = tmp_path / name
    p.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    return p


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------


def test_install_writes_fresh_policies_when_none_exists(tmp_path: Path) -> None:
    tbb = _make_tbb(tmp_path)
    ca = _make_ca(tmp_path)
    snap = tmp_path / "snap"

    install_certificate_policy(tbb, ca, snap)

    target = policies_path(tbb)
    data = json.loads(target.read_text("utf-8"))
    assert data["policies"]["Certificates"]["Install"] == [str(ca)]
    # Marker recorded so restore knows there was no prior file.
    assert (snap / "no-prior-policies.flag").is_file()
    assert not (snap / "policies.json.bak").exists()


def test_install_deep_merges_with_unrelated_existing_keys(tmp_path: Path) -> None:
    tbb = _make_tbb(tmp_path)
    ca = _make_ca(tmp_path)
    snap = tmp_path / "snap"
    target = policies_path(tbb)
    prior = {"policies": {"BlockAboutConfig": True}}
    target.write_text(json.dumps(prior), encoding="utf-8")

    install_certificate_policy(tbb, ca, snap)

    data = json.loads(target.read_text("utf-8"))
    assert data["policies"]["BlockAboutConfig"] is True
    assert data["policies"]["Certificates"]["Install"] == [str(ca)]
    # Snapshot saved.
    snapshot = (snap / "policies.json.bak").read_text("utf-8")
    assert json.loads(snapshot) == prior
    assert not (snap / "no-prior-policies.flag").exists()


def test_install_appends_to_existing_certificates_install_list(tmp_path: Path) -> None:
    tbb = _make_tbb(tmp_path)
    ca = _make_ca(tmp_path)
    snap = tmp_path / "snap"
    target = policies_path(tbb)
    prior = {
        "policies": {
            "Certificates": {
                "ImportEnterpriseRoots": True,
                "Install": ["/etc/other-ca.pem"],
            }
        }
    }
    target.write_text(json.dumps(prior), encoding="utf-8")

    install_certificate_policy(tbb, ca, snap)

    data = json.loads(target.read_text("utf-8"))
    install = data["policies"]["Certificates"]["Install"]
    assert install == ["/etc/other-ca.pem", str(ca)]
    # Existing toggle preserved (not silently flipped to False).
    assert data["policies"]["Certificates"]["ImportEnterpriseRoots"] is True


def test_install_does_not_double_add_existing_path(tmp_path: Path) -> None:
    tbb = _make_tbb(tmp_path)
    ca = _make_ca(tmp_path)
    snap = tmp_path / "snap"
    target = policies_path(tbb)
    prior = {"policies": {"Certificates": {"Install": [str(ca)]}}}
    target.write_text(json.dumps(prior), encoding="utf-8")

    install_certificate_policy(tbb, ca, snap)

    data = json.loads(target.read_text("utf-8"))
    assert data["policies"]["Certificates"]["Install"] == [str(ca)]
    # Snapshot still saved so restore can return the file untouched.
    snapshot = json.loads((snap / "policies.json.bak").read_text("utf-8"))
    assert snapshot == prior


def test_install_rejects_malformed_json(tmp_path: Path) -> None:
    tbb = _make_tbb(tmp_path)
    ca = _make_ca(tmp_path)
    target = policies_path(tbb)
    target.write_text("{not json", encoding="utf-8")
    with pytest.raises(ProxyInterceptError):
        install_certificate_policy(tbb, ca, tmp_path / "snap")


def test_install_refuses_unwritable_dist_dir(tmp_path: Path, monkeypatch) -> None:
    tbb = _make_tbb(tmp_path)
    ca = _make_ca(tmp_path)

    import torbrowser_driver._proxy_intercept_policies as mod

    def _boom(_dist_dir):
        raise ProxyInterceptError(
            "policies.json install path not writable: " + str(_dist_dir)
        )

    monkeypatch.setattr(mod, "_assert_writable", _boom)

    with pytest.raises(ProxyInterceptError) as ei:
        install_certificate_policy(tbb, ca, tmp_path / "snap")
    assert "not writable" in str(ei.value)
    assert str(tbb / "Browser" / "distribution") in str(ei.value)


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def test_restore_round_trips_byte_equivalent_when_prior_existed(tmp_path: Path) -> None:
    tbb = _make_tbb(tmp_path)
    ca = _make_ca(tmp_path)
    snap = tmp_path / "snap"
    target = policies_path(tbb)
    prior_text = json.dumps({"policies": {"BlockAboutConfig": True}}, indent=4)
    target.write_text(prior_text, encoding="utf-8")
    prior_bytes = target.read_bytes()

    install_certificate_policy(tbb, ca, snap)
    assert target.read_bytes() != prior_bytes  # sanity: write happened
    restore_certificate_policy(tbb, snap)

    assert target.read_bytes() == prior_bytes


def test_restore_deletes_policies_when_no_prior_file(tmp_path: Path) -> None:
    tbb = _make_tbb(tmp_path)
    ca = _make_ca(tmp_path)
    snap = tmp_path / "snap"
    target = policies_path(tbb)
    assert not target.exists()

    install_certificate_policy(tbb, ca, snap)
    assert target.exists()
    restore_certificate_policy(tbb, snap)
    assert not target.exists()
    # Marker is consumed.
    assert not (snap / "no-prior-policies.flag").exists()


def test_restore_logs_and_marks_stale_when_snapshot_missing(
    tmp_path: Path, caplog
) -> None:
    tbb = _make_tbb(tmp_path)
    target = policies_path(tbb)
    target.write_text('{"policies": {}}', encoding="utf-8")
    snap = tmp_path / "empty-snap"
    snap.mkdir()

    with caplog.at_level(logging.WARNING):
        restore_certificate_policy(tbb, snap)

    assert target.is_file()  # left in place
    assert any("stale-policy" in rec.message for rec in caplog.records)
    stale = target.with_suffix(target.suffix + ".tor-browser-mcp-stale-policy")
    assert stale.is_file()


def test_restore_swallows_exceptions_from_inner_calls(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    tbb = _make_tbb(tmp_path)
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "policies.json.bak").write_text('{"policies": {}}', encoding="utf-8")

    target = policies_path(tbb)

    class _BoomPath:
        pass

    original_write_bytes = Path.write_bytes

    def _boom(self, data):
        if self == target:
            raise OSError("disk full")
        return original_write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", _boom)
    with caplog.at_level(logging.ERROR):
        restore_certificate_policy(tbb, snap)  # must not raise
    assert any("restore failed" in rec.message for rec in caplog.records)
