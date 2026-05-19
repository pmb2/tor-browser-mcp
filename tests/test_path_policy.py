"""Unit tests for the filesystem path policy."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.request import pathname2url

import pytest

from torbrowser_driver import PathNotAllowed, PathPolicy


@pytest.fixture
def workspace(tmp_path: Path) -> dict[str, Path]:
    out = tmp_path / "out"
    root_a = tmp_path / "root_a"
    root_b = tmp_path / "root_b"
    outside = tmp_path / "outside"
    for d in (out, root_a, root_b, outside):
        d.mkdir()
    (root_a / "alpha.txt").write_text("a")
    (root_b / "nested" / "sub").mkdir(parents=True)
    (root_b / "nested" / "sub" / "beta.txt").write_text("b")
    (outside / "secret.txt").write_text("nope")
    return {
        "tmp": tmp_path,
        "out": out,
        "root_a": root_a,
        "root_b": root_b,
        "outside": outside,
    }


def _policy(workspace: dict[str, Path], **overrides) -> PathPolicy:
    return PathPolicy.from_config(
        output_dir=workspace["out"],
        allowed_roots=[workspace["root_a"], workspace["root_b"]],
        **overrides,
    )


def test_resolve_input_under_output_dir(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    target = workspace["out"] / "snapshot.png"
    target.write_bytes(b"")
    resolved = policy.resolve_input(target)
    assert resolved == target.resolve()


def test_resolve_input_under_each_allowed_root(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    a = policy.resolve_input(workspace["root_a"] / "alpha.txt")
    b = policy.resolve_input(workspace["root_b"] / "nested" / "sub" / "beta.txt")
    assert a.name == "alpha.txt"
    assert b.name == "beta.txt"


def test_resolve_input_denies_outside(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    with pytest.raises(PathNotAllowed):
        policy.resolve_input(workspace["outside"] / "secret.txt")


def test_resolve_input_denies_dotdot_traversal(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    sneaky = workspace["root_a"] / ".." / "outside" / "secret.txt"
    with pytest.raises(PathNotAllowed):
        policy.resolve_input(sneaky)


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="POSIX symlink creation"
)
def test_symlink_to_outside_is_denied(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    link = workspace["root_a"] / "escape"
    os.symlink(workspace["outside"], link)
    with pytest.raises(PathNotAllowed):
        policy.resolve_input(link / "secret.txt")


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="POSIX symlink creation"
)
def test_symlink_to_inside_is_allowed(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    link = workspace["root_a"] / "inward"
    os.symlink(workspace["root_b"], link)
    resolved = policy.resolve_input(link / "nested" / "sub" / "beta.txt")
    assert resolved.name == "beta.txt"


def test_unrestricted_bypasses_input_checks(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace, unrestricted=True)
    resolved = policy.resolve_input(workspace["outside"] / "secret.txt")
    assert resolved == (workspace["outside"] / "secret.txt").resolve()


def test_resolve_output_relative_joins_output_dir(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    p = policy.resolve_output("shots/page.png")
    assert p == (workspace["out"] / "shots" / "page.png").resolve()
    assert p.parent.is_dir()


def test_resolve_output_rejects_relative_escape(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    with pytest.raises(PathNotAllowed):
        policy.resolve_output("../outside/oops.png")


def test_resolve_output_absolute_under_output_dir(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    abs_path = workspace["out"] / "deep" / "file.txt"
    p = policy.resolve_output(abs_path)
    assert p == abs_path.resolve()


def test_resolve_output_absolute_outside_is_denied(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    with pytest.raises(PathNotAllowed):
        policy.resolve_output(workspace["outside"] / "foo.txt")


def test_resolve_output_absolute_in_allowed_root_is_permitted(
    workspace: dict[str, Path],
) -> None:
    policy = _policy(workspace)
    target = workspace["root_a"] / "stored.txt"
    p = policy.resolve_output(target)
    assert p == target.resolve()


def test_unrestricted_allows_arbitrary_output(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace, unrestricted=True)
    target = workspace["outside"] / "anywhere.txt"
    p = policy.resolve_output(target)
    assert p == target.resolve()


def test_file_url_allowed_for_input_path(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    url = "file:" + pathname2url(str(workspace["root_a"] / "alpha.txt"))
    assert policy.is_file_url_allowed(url) is True


def test_file_url_denied_for_outside_path(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    url = "file:" + pathname2url(str(workspace["outside"] / "secret.txt"))
    assert policy.is_file_url_allowed(url) is False


def test_file_url_with_remote_host_is_denied(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    assert policy.is_file_url_allowed("file://evil.example/secret") is False


def test_non_file_scheme_is_passthrough(workspace: dict[str, Path]) -> None:
    policy = _policy(workspace)
    assert policy.is_file_url_allowed("https://example.com/") is True


def test_from_config_falls_back_to_cwd(tmp_path: Path) -> None:
    out = tmp_path / "out"
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = PathPolicy.from_config(output_dir=out, cwd=cwd)
    inside = cwd / "file.txt"
    inside.write_text("ok")
    assert policy.resolve_input(inside) == inside.resolve()


def test_from_config_mcp_roots_take_precedence_over_cwd(tmp_path: Path) -> None:
    out = tmp_path / "out"
    mcp = tmp_path / "mcp"
    mcp.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    policy = PathPolicy.from_config(
        output_dir=out, mcp_roots=[mcp], cwd=other
    )
    with pytest.raises(PathNotAllowed):
        policy.resolve_input(other / "x.txt")
    (mcp / "y.txt").write_text("ok")
    assert policy.resolve_input(mcp / "y.txt").name == "y.txt"
