"""Tests for the ``unsafe`` capability driver primitives."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from torbrowser_driver import PathPolicy, TorBrowserDriver


class _FakeConfig(SimpleNamespace):
    pass


@pytest.fixture()
def policy(tmp_path: Path) -> PathPolicy:
    out = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    return PathPolicy.from_config(output_dir=out, cwd=work)


@pytest.fixture()
def drv(policy: PathPolicy) -> TorBrowserDriver:
    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = _FakeConfig(path_policy=policy)  # type: ignore[assignment]
    instance.webdriver = MagicMock(name="webdriver")
    instance.controller = MagicMock(name="controller")
    instance._closed = False
    instance._tor_process = None
    instance._session_dir = None
    instance._owns_session_dir = False
    instance._owns_tor_data_dir = False
    return instance


def test_browser_chrome_evaluate_unsafe_switches_contexts(drv: TorBrowserDriver) -> None:
    order: list[str] = []
    drv.webdriver.set_context.side_effect = lambda c: order.append(f"set:{c}")
    drv.webdriver.execute_script.side_effect = (
        lambda *a, **k: order.append("exec") or "ok"
    )

    result = drv.browser_chrome_evaluate_unsafe("return 1")
    assert result == {"result": "ok"}
    assert order == ["set:chrome", "exec", "set:content"]


def test_browser_chrome_evaluate_unsafe_restores_context_on_error(
    drv: TorBrowserDriver,
) -> None:
    drv.webdriver.execute_script.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError, match="boom"):
        drv.browser_chrome_evaluate_unsafe("throw 1")
    # set_context called with "chrome" then "content"
    contexts = [c.args[0] for c in drv.webdriver.set_context.call_args_list]
    assert contexts == ["chrome", "content"]


def test_browser_chrome_evaluate_unsafe_writes_filename(
    drv: TorBrowserDriver, policy: PathPolicy
) -> None:
    drv.webdriver.execute_script.return_value = {"value": 42}
    result = drv.browser_chrome_evaluate_unsafe("return 42", filename="out.json")
    assert result["result"] == {"value": 42}
    written = Path(result["path"])
    assert written.exists()
    assert written.read_text(encoding="utf-8") == '{"value": 42}'


def test_browser_run_python_unsafe_captures_stdout(drv: TorBrowserDriver) -> None:
    result = drv.browser_run_python_unsafe(code="print('hi')")
    assert result["stdout"] == "hi\n"
    g = result["globals"]
    assert "driver" in g
    assert "webdriver" in g
    assert "controller" in g
    assert "config" in g
    assert "path_policy" in g
    assert "output_dir" in g


def test_browser_run_python_unsafe_sees_defined_names(drv: TorBrowserDriver) -> None:
    result = drv.browser_run_python_unsafe(code="x = 1 + 2\nprint(x)")
    assert result["stdout"] == "3\n"
    assert result["globals"]["x"] == "3"


def test_browser_run_python_unsafe_requires_exactly_one_input(
    drv: TorBrowserDriver,
) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        drv.browser_run_python_unsafe()
    with pytest.raises(ValueError, match="exactly one"):
        drv.browser_run_python_unsafe(code="pass", filename="x.py")


def test_browser_run_python_unsafe_reads_file(
    drv: TorBrowserDriver, tmp_path: Path, policy: PathPolicy
) -> None:
    script = policy.output_dir / "snippet.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("print('from-file')\n", encoding="utf-8")

    result = drv.browser_run_python_unsafe(filename=str(script))
    assert result["stdout"] == "from-file\n"


def test_browser_run_python_unsafe_propagates_exceptions(
    drv: TorBrowserDriver,
) -> None:
    with pytest.raises(ZeroDivisionError):
        drv.browser_run_python_unsafe(code="1/0")


def test_tor_control_command_unsafe_calls_msg(drv: TorBrowserDriver) -> None:
    response = MagicMock(name="ControlResponse")
    response.is_ok.return_value = True
    response.__str__ = lambda self: "250 OK"  # type: ignore[assignment,method-assign]
    drv.controller.msg.return_value = response

    result = drv.tor_control_command_unsafe("GETINFO version")
    drv.controller.msg.assert_called_once_with("GETINFO version")
    assert result == {
        "command": "GETINFO version",
        "raw": "250 OK",
        "is_ok": True,
    }


def test_tor_control_command_unsafe_requires_controller(policy: PathPolicy) -> None:
    instance = TorBrowserDriver.__new__(TorBrowserDriver)
    instance.config = _FakeConfig(path_policy=policy)  # type: ignore[assignment]
    instance.webdriver = MagicMock()
    instance.controller = None
    with pytest.raises(RuntimeError, match="controller not started"):
        instance.tor_control_command_unsafe("GETINFO version")
