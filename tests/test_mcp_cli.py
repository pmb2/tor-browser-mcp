"""Unit tests for the torbrowser_mcp CLI argparse and config builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from torbrowser_mcp.cli import build_parser, config_from_args, parse_args


@pytest.fixture()
def out_dir(tmp_path: Path) -> Path:
    return tmp_path / "out"


def test_parser_accepts_full_flag_set(fake_tbb_layout: Path, out_dir: Path, tmp_path: Path) -> None:
    extra = tmp_path / "extra"
    extra.mkdir()
    ns = parse_args(
        [
            "--tbb-root", str(fake_tbb_layout),
            "--output-dir", str(out_dir),
            "--allowed-root", str(extra),
            "--caps", "vision,pdf",
            "--socks-port", "12345",
            "--control-port", "12346",
            "--profile-mode", "ephemeral",
            "--headless",
            "--log-level", "debug",
            "--transport", "stdio",
        ]
    )
    assert ns.tbb_root == fake_tbb_layout
    assert ns.output_dir == out_dir
    assert ns.allowed_roots == [extra]
    assert ns.caps == "vision,pdf"
    assert ns.socks_port == 12345
    assert ns.headless is True
    assert ns.log_level == "debug"


def test_tbb_root_from_env(
    monkeypatch: pytest.MonkeyPatch, fake_tbb_layout: Path, out_dir: Path
) -> None:
    monkeypatch.setenv("TBB_ROOT", str(fake_tbb_layout))
    ns = parse_args(["--output-dir", str(out_dir)])
    config, _ = config_from_args(ns)
    assert config.tbb_root == fake_tbb_layout.resolve()


def test_missing_tbb_root_errors(
    monkeypatch: pytest.MonkeyPatch, out_dir: Path
) -> None:
    monkeypatch.delenv("TBB_ROOT", raising=False)
    ns = parse_args(["--output-dir", str(out_dir)])
    with pytest.raises(SystemExit) as info:
        config_from_args(ns)
    assert info.value.code == 2


def test_caps_combined_with_defaults(fake_tbb_layout: Path, out_dir: Path) -> None:
    ns = parse_args(
        [
            "--tbb-root", str(fake_tbb_layout),
            "--output-dir", str(out_dir),
            "--caps", "vision,pdf",
        ]
    )
    config, _ = config_from_args(ns)
    assert "vision" in config.enabled_caps
    assert "pdf" in config.enabled_caps
    assert "core" in config.enabled_caps
    assert "state" in config.enabled_caps


def test_unsafe_flag_adds_cap(fake_tbb_layout: Path, out_dir: Path) -> None:
    ns = parse_args(
        ["--tbb-root", str(fake_tbb_layout), "--output-dir", str(out_dir), "--unsafe"]
    )
    config, _ = config_from_args(ns)
    assert "unsafe" in config.enabled_caps


def test_unknown_cap_errors(fake_tbb_layout: Path, out_dir: Path) -> None:
    ns = parse_args(
        [
            "--tbb-root", str(fake_tbb_layout),
            "--output-dir", str(out_dir),
            "--caps", "nope",
        ]
    )
    with pytest.raises(SystemExit) as info:
        config_from_args(ns)
    assert info.value.code == 2


def test_default_cap_not_acceptable_in_caps(fake_tbb_layout: Path, out_dir: Path) -> None:
    ns = parse_args(
        [
            "--tbb-root", str(fake_tbb_layout),
            "--output-dir", str(out_dir),
            "--caps", "core",
        ]
    )
    with pytest.raises(SystemExit) as info:
        config_from_args(ns)
    assert info.value.code == 2


def test_persistent_requires_profile_path(fake_tbb_layout: Path, out_dir: Path) -> None:
    ns = parse_args(
        [
            "--tbb-root", str(fake_tbb_layout),
            "--output-dir", str(out_dir),
            "--profile-mode", "persistent",
        ]
    )
    with pytest.raises(SystemExit) as info:
        config_from_args(ns)
    assert info.value.code == 2


def test_allowed_root_repeats(
    fake_tbb_layout: Path, out_dir: Path, tmp_path: Path
) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    ns = parse_args(
        [
            "--tbb-root", str(fake_tbb_layout),
            "--output-dir", str(out_dir),
            "--allowed-root", str(one),
            "--allowed-root", str(two),
        ]
    )
    config, _ = config_from_args(ns)
    roots = set(config.path_policy.allowed_roots)
    assert one.resolve() in roots
    assert two.resolve() in roots


def test_allow_unrestricted_file_access_sets_flag(
    fake_tbb_layout: Path, out_dir: Path
) -> None:
    ns = parse_args(
        [
            "--tbb-root", str(fake_tbb_layout),
            "--output-dir", str(out_dir),
            "--allow-unrestricted-file-access",
        ]
    )
    config, _ = config_from_args(ns)
    assert config.path_policy.unrestricted is True


def test_output_dir_is_created(fake_tbb_layout: Path, tmp_path: Path) -> None:
    nested = tmp_path / "out" / "nested"
    ns = parse_args(["--tbb-root", str(fake_tbb_layout), "--output-dir", str(nested)])
    config, _ = config_from_args(ns)
    assert nested.is_dir()
    assert config.path_policy.output_dir == nested.resolve()


def test_tool_module_collected(fake_tbb_layout: Path, out_dir: Path, tmp_path: Path) -> None:
    mod = tmp_path / "ext.py"
    mod.write_text("def register(ctx):\n    pass\n", encoding="utf-8")
    ns = parse_args(
        [
            "--tbb-root", str(fake_tbb_layout),
            "--output-dir", str(out_dir),
            "--tool-module", str(mod),
        ]
    )
    _, options = config_from_args(ns)
    assert options.tool_modules == (mod.resolve(),)


def test_parser_help_runs() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as info:
        parser.parse_args(["--help"])
    assert info.value.code == 0
