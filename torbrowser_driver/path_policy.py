"""Filesystem path policy.

A guardrail (not a sandbox) that scopes every path-accepting tool to a
configured output directory plus an explicit set of allowed roots. Inputs
are normalised through :meth:`pathlib.Path.resolve` so that ``..`` segments,
symlinks, and Windows drive variations all collapse to a canonical absolute
path before the containment check runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from .exceptions import PathNotAllowed

if TYPE_CHECKING:
    from collections.abc import Iterable


def _canonical(path: Path) -> Path:
    """Return an absolute, symlink-resolved path that may or may not exist."""

    return Path(path).expanduser().resolve(strict=False)


def _is_within(candidate: Path, root: Path) -> bool:
    candidate = _canonical(candidate)
    root = _canonical(root)
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class PathPolicy:
    """Scope filesystem reads, writes, and ``file://`` navigation.

    Attributes:
        output_dir: Canonical directory for tool-produced files. Always allowed
            for both reads and writes.
        allowed_roots: Additional canonical directories that are allowed for
            reads (and writes, if an absolute path lands inside one).
        unrestricted: When ``True``, every check returns the canonical path
            without containment validation. Reserved for the
            ``--allow-unrestricted-file-access`` opt-in.
    """

    output_dir: Path
    allowed_roots: tuple[Path, ...] = field(default_factory=tuple)
    unrestricted: bool = False

    @classmethod
    def from_config(
        cls,
        *,
        output_dir: str | Path,
        mcp_roots: Iterable[str | Path] | None = None,
        allowed_roots: Iterable[str | Path] | None = None,
        cwd: str | Path | None = None,
        unrestricted: bool = False,
    ) -> PathPolicy:
        """Build a policy from the same inputs the CLI/MCP layer will surface.

        ``output_dir`` is always allowed. ``mcp_roots`` (client-provided MCP
        roots, if any) and ``allowed_roots`` (``--allowed-root`` CLI flags)
        extend the allow-list. ``cwd`` is used as a fallback when neither
        ``mcp_roots`` nor ``allowed_roots`` provide any entries.
        """

        out = _canonical(Path(output_dir))
        out.mkdir(parents=True, exist_ok=True)

        roots: list[Path] = []
        seen: set[Path] = set()

        def _add(p: str | Path) -> None:
            canonical = _canonical(Path(p))
            if canonical not in seen:
                seen.add(canonical)
                roots.append(canonical)

        if mcp_roots:
            for p in mcp_roots:
                _add(p)
        if allowed_roots:
            for p in allowed_roots:
                _add(p)
        if not roots and cwd is not None:
            _add(cwd)

        return cls(
            output_dir=out,
            allowed_roots=tuple(roots),
            unrestricted=bool(unrestricted),
        )

    def _all_roots(self) -> tuple[Path, ...]:
        return (self.output_dir, *self.allowed_roots)

    def resolve_input(self, path: str | Path) -> Path:
        """Resolve ``path`` for reading or uploading.

        Raises :class:`PathNotAllowed` unless the canonical path is within
        :attr:`output_dir` or one of :attr:`allowed_roots`. When
        :attr:`unrestricted` is set, the path is returned without any
        containment check.
        """

        candidate = _canonical(Path(path))
        if self.unrestricted:
            return candidate
        for root in self._all_roots():
            if _is_within(candidate, root):
                return candidate
        raise PathNotAllowed(
            f"path {candidate!s} is outside the allowed roots: "
            f"{', '.join(str(r) for r in self._all_roots())}"
        )

    def resolve_output(self, filename: str | Path) -> Path:
        """Resolve ``filename`` for an output-dir-scoped write.

        Relative names are joined to :attr:`output_dir`. Absolute paths are
        accepted only if they fall under :attr:`output_dir` (or any allowed
        root when :attr:`unrestricted` is set, or when the absolute path
        happens to lie under an allowed root). Parent directories are created
        lazily so callers can write immediately.
        """

        raw = Path(filename)
        if raw.is_absolute():
            candidate = _canonical(raw)
            if (
                self.unrestricted
                or _is_within(candidate, self.output_dir)
                or any(_is_within(candidate, r) for r in self.allowed_roots)
            ):
                resolved = candidate
            else:
                raise PathNotAllowed(
                    f"output path {candidate!s} is not under output_dir "
                    f"{self.output_dir!s} or an allowed root"
                )
        else:
            # Reject "../" escape attempts by checking the joined canonical
            # path still sits under output_dir.
            joined = _canonical(self.output_dir / raw)
            if not self.unrestricted and not _is_within(joined, self.output_dir):
                raise PathNotAllowed(
                    f"output filename {filename!s} escapes output_dir "
                    f"{self.output_dir!s}"
                )
            resolved = joined

        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved

    def is_file_url_allowed(self, url: str) -> bool:
        """Return whether a ``file://`` URL resolves to an allowed path.

        Non-``file`` URLs are always permitted by this method; the caller
        decides their own scheme policy. ``file://`` URLs with a remote host
        component (anything other than empty or ``localhost``) are rejected.
        """

        parsed = urlparse(url)
        if parsed.scheme.lower() != "file":
            return True
        if self.unrestricted:
            return True
        if parsed.netloc and parsed.netloc.lower() not in ("", "localhost"):
            return False
        local = url2pathname(unquote(parsed.path))
        try:
            self.resolve_input(local)
        except PathNotAllowed:
            return False
        return True
