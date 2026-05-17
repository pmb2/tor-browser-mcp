"""Escape-hatch primitives implementing the ``unsafe`` capability.

Every tool here is RCE-equivalent: chrome-context JavaScript, in-process
Python ``exec``, and unfiltered tor control commands. They are opt-in via
``--unsafe`` on the CLI and exist for trusted local research workflows.
The docstrings begin with ``Unsafe:`` so the warning surfaces in the
generated MCP tool descriptions.
"""

from __future__ import annotations

import contextlib
import io
import json
from typing import TYPE_CHECKING, Any

from .capabilities import capability

if TYPE_CHECKING:
    from selenium import webdriver
    from stem.control import Controller

    from .config import DriverConfig
    from .path_policy import PathPolicy


class _UnsafeCapabilityMixin:
    """Implements the ``unsafe`` capability surface on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: "webdriver.Firefox | None"
        controller: "Controller | None"
        config: "DriverConfig"

        def _require_driver(self) -> "webdriver.Firefox": ...
        def _require_controller(self) -> "Controller": ...

    @capability("unsafe")
    def browser_chrome_evaluate_unsafe(
        self,
        script: str,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Unsafe: run ``script`` in the Firefox chrome (browser-UI) context.

        Switches the Marionette context to ``chrome`` for the duration of
        the call, executes ``script`` via ``execute_script``, and restores
        the ``content`` context in a ``finally``. Chrome-context scripts
        can read arbitrary preferences, drive the browser UI, and reach
        into XPCOM - treat the input as fully trusted. When ``filename``
        is given the JSON-encoded result is also written under the output
        directory.
        """

        drv = self._require_driver()
        drv.set_context("chrome")
        try:
            result = drv.execute_script(script)
        finally:
            drv.set_context("content")

        if filename is not None:
            path = self.config.path_policy.resolve_output(filename)
            data = json.dumps(result, ensure_ascii=False, default=str).encode("utf-8")
            path.write_bytes(data)
            return {"result": result, "path": str(path), "bytes": len(data)}
        return {"result": result}

    @capability("unsafe")
    def browser_run_python_unsafe(
        self,
        code: str | None = None,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """Unsafe: ``exec`` Python in the running MCP server process.

        Exactly one of ``code`` or ``filename`` must be provided. The
        executed snippet sees ``driver`` (the :class:`TorBrowserDriver`),
        ``webdriver`` (the Selenium handle), ``controller`` (the stem
        controller, possibly ``None``), ``config``, ``path_policy``, and
        ``output_dir`` as globals. ``stdout`` is captured into the return
        payload; the ``globals`` field is a ``repr`` view of the post-run
        globals so the agent can see what the snippet defined. Exceptions
        from the user code propagate.
        """

        if (code is None) == (filename is None):
            raise ValueError(
                "browser_run_python_unsafe needs exactly one of code or filename"
            )

        if filename is not None:
            path = self.config.path_policy.resolve_input(filename)
            source = path.read_text(encoding="utf-8")
        else:
            source = code  # type: ignore[assignment]

        path_policy: "PathPolicy" = self.config.path_policy
        globals_dict: dict[str, Any] = {
            "__name__": "__tbm_unsafe__",
            "driver": self,
            "webdriver": getattr(self, "webdriver", None),
            "controller": getattr(self, "controller", None),
            "config": self.config,
            "path_policy": path_policy,
            "output_dir": path_policy.output_dir,
        }

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(source, globals_dict)
        captured = buf.getvalue()
        reflected = {
            k: repr(v) for k, v in globals_dict.items() if not k.startswith("_")
        }
        return {"stdout": captured, "globals": reflected}

    @capability("unsafe")
    def tor_control_command_unsafe(self, command: str) -> dict[str, Any]:
        """Unsafe: send a raw control command to the bundled tor.

        Bypasses the :data:`_GETINFO_ALLOWLIST` enforced by
        :meth:`tor_get_info` and accepts any verb the controller will
        honour, including ``SETCONF``, ``SIGNAL HALT``, and
        ``EXTENDCIRCUIT`` variants that can crash or partition tor.
        Returns the raw control-line response plus its ``is_ok()``
        verdict.
        """

        ctrl = self._require_controller()
        response = ctrl.msg(command)
        return {
            "command": command,
            "raw": str(response),
            "is_ok": bool(response.is_ok()),
        }
