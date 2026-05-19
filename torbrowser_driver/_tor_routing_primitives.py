"""Routing-policy primitives implementing the ``tor-routing`` capability.

These tools issue ``SETCONF`` / ``RESETCONF`` commands against the bundled
tor's controller to pin or release exit selection. Every method narrows
the anonymity set relative to default Tor Browser behaviour; the
docstrings call that out so the cost is visible at the tool surface.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .capabilities import capability
from .exceptions import TorBrowserDriverError

if TYPE_CHECKING:
    from stem.control import Controller

    from .config import DriverConfig


_COUNTRY_RE = re.compile(r"[A-Za-z]{2}")
_FINGERPRINT_RE = re.compile(r"[0-9A-Fa-f]{40}")
_NICKNAME_RE = re.compile(r"[A-Za-z0-9]{1,19}")


def _format_node(node: str) -> str:
    stripped = node.lstrip("$")
    if _FINGERPRINT_RE.fullmatch(stripped):
        return "$" + stripped.upper()
    if _NICKNAME_RE.fullmatch(node):
        return node
    raise ValueError(
        f"invalid exit-node identifier {node!r}; expected a 40-hex fingerprint "
        f"(optionally $-prefixed) or a 1-19 character nickname"
    )


class _TorRoutingCapabilityMixin:
    """Implements the ``tor-routing`` capability surface on :class:`TorBrowserDriver`.

    Carries its own thin :meth:`_require_controller` rather than importing
    from :class:`_TorCapabilityMixin` so the two routing tiers stay
    composition-independent. The base ``tor`` capability and this one are
    enabled and disabled separately.
    """

    if TYPE_CHECKING:
        controller: Controller | None
        config: DriverConfig

    def _require_controller(self) -> Controller:
        ctrl = getattr(self, "controller", None)
        if ctrl is None:
            raise TorBrowserDriverError(
                "controller not started; use TorBrowserDriver as a context manager"
            )
        return ctrl

    @capability("tor-routing")
    def tor_set_exit_country(
        self, country_code: str, strict: bool = False
    ) -> dict[str, Any]:
        """Pin tor's exit selection to a two-letter ISO country, narrowing
        the anonymity set so subsequent circuits exit only through relays
        in the requested country and the session becomes distinguishable
        from default Tor Browser use.

        Callers should pair this with ``tor_new_identity`` to actually
        rotate onto a fresh circuit through the requested exit.
        ``strict=True`` forbids tor from falling back to other countries
        when no exit is usable; ``False`` lets it relax the constraint
        under pressure.
        """

        if not _COUNTRY_RE.fullmatch(country_code):
            raise ValueError(
                f"invalid country code {country_code!r}; expected two ASCII letters"
            )
        cc = country_code.upper()
        ctrl = self._require_controller()
        previous = {
            "ExitNodes": ctrl.get_conf("ExitNodes", ""),
            "StrictNodes": ctrl.get_conf("StrictNodes", "0"),
        }
        ctrl.set_conf("ExitNodes", "{" + cc + "}")
        ctrl.set_conf("StrictNodes", "1" if strict else "0")
        return {
            "exit_country": cc,
            "strict": bool(strict),
            "previous": previous,
        }

    @capability("tor-routing")
    def tor_set_exit_nodes(
        self, nodes: list[str], strict: bool = False
    ) -> dict[str, Any]:
        """Pin tor's exit selection to a specific set of relays, sharply
        narrowing the anonymity set and making the session distinguishable
        from default Tor Browser use; a small or stale fingerprint list
        can also break exit availability entirely.

        Accepts entries as 40-hex fingerprints (with or without a leading
        ``$``) or as 1-19 character relay nicknames; any other token
        raises ``ValueError``. Pair with ``tor_new_identity`` to use the
        new policy. ``strict=True`` forbids tor from relaxing the
        constraint.
        """

        if not nodes:
            raise ValueError("nodes must contain at least one entry")
        formatted = [_format_node(n) for n in nodes]
        ctrl = self._require_controller()
        previous = {
            "ExitNodes": ctrl.get_conf("ExitNodes", ""),
            "StrictNodes": ctrl.get_conf("StrictNodes", "0"),
        }
        ctrl.set_conf("ExitNodes", ",".join(formatted))
        ctrl.set_conf("StrictNodes", "1" if strict else "0")
        return {
            "exit_nodes": formatted,
            "strict": bool(strict),
            "previous": previous,
        }

    @capability("tor-routing")
    def tor_clear_exit_policy(self) -> dict[str, Any]:
        """Reset every routing-narrowing option to its default.

        Issues ``RESETCONF`` for ``ExitNodes``, ``StrictNodes``,
        ``ExcludeExitNodes``, ``EntryNodes``, and ``ExcludeNodes`` so the
        controller-level pinning installed by the other ``tor-routing``
        tools is fully cleared in one call.
        """

        ctrl = self._require_controller()
        cleared = [
            "ExitNodes",
            "StrictNodes",
            "ExcludeExitNodes",
            "EntryNodes",
            "ExcludeNodes",
        ]
        ctrl.reset_conf(*cleared)
        return {"cleared": cleared}
