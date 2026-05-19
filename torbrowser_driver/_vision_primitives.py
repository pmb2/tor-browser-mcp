"""Coordinate-based input primitives implementing the ``vision`` capability.

These methods drive Selenium's W3C ``ActionBuilder`` so callers can issue
mouse moves, clicks, drags, and wheel events at absolute viewport
coordinates. They exist for agents that have a screenshot but no usable
CSS selector for the target.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.actions.mouse_button import MouseButton

from .capabilities import capability

if TYPE_CHECKING:
    from selenium import webdriver

    from .config import DriverConfig


_BUTTONS: dict[str, int] = {
    "left": MouseButton.LEFT,
    "middle": MouseButton.MIDDLE,
    "right": MouseButton.RIGHT,
}


def _resolve_button(button: str) -> int:
    key = button.lower()
    if key not in _BUTTONS:
        raise ValueError(
            f"unsupported button {button!r}; expected one of {sorted(_BUTTONS)}"
        )
    return _BUTTONS[key]


class _VisionCapabilityMixin:
    """Implements the ``vision`` capability surface on :class:`TorBrowserDriver`."""

    if TYPE_CHECKING:
        webdriver: webdriver.Firefox | None
        config: DriverConfig

        def _require_driver(self) -> webdriver.Firefox: ...

    @capability("vision")
    def browser_mouse_move_xy(self, x: int, y: int) -> dict[str, Any]:
        """Move the mouse pointer to the viewport coordinates ``(x, y)``."""

        drv = self._require_driver()
        actions = ActionChains(drv)
        actions.w3c_actions.pointer_action.move_to_location(int(x), int(y))
        actions.perform()
        return {"x": int(x), "y": int(y)}

    @capability("vision")
    def browser_mouse_click_xy(
        self,
        x: int,
        y: int,
        button: Literal["left", "middle", "right"] = "left",
        click_count: int = 1,
        delay: float = 0.0,
    ) -> dict[str, Any]:
        """Click at viewport coordinates ``(x, y)``.

        ``click_count=2`` performs a double-click; values above 2 issue
        that many sequential clicks with ``delay`` seconds between each.
        ``button`` accepts ``"left" | "middle" | "right"``.
        """

        drv = self._require_driver()
        btn = _resolve_button(button)
        count = max(1, int(click_count))
        actions = ActionChains(drv)
        actions.w3c_actions.pointer_action.move_to_location(int(x), int(y))
        for i in range(count):
            actions.w3c_actions.pointer_action.pointer_down(btn)
            actions.w3c_actions.pointer_action.pointer_up(btn)
            if i < count - 1 and delay > 0:
                actions.w3c_actions.pointer_action.pause(float(delay))
        actions.perform()
        return {"x": int(x), "y": int(y), "button": button.lower(), "clicks": count}

    @capability("vision")
    def browser_mouse_down(
        self,
        x: int,
        y: int,
        button: Literal["left", "middle", "right"] = "left",
    ) -> dict[str, Any]:
        """Move to ``(x, y)``, press ``button``, and leave it held."""

        drv = self._require_driver()
        btn = _resolve_button(button)
        actions = ActionChains(drv)
        actions.w3c_actions.pointer_action.move_to_location(int(x), int(y))
        actions.w3c_actions.pointer_action.pointer_down(btn)
        actions.perform()
        return {"x": int(x), "y": int(y), "button": button.lower()}

    @capability("vision")
    def browser_mouse_up(
        self,
        x: int,
        y: int,
        button: Literal["left", "middle", "right"] = "left",
    ) -> dict[str, Any]:
        """Move to ``(x, y)`` and release ``button``."""

        drv = self._require_driver()
        btn = _resolve_button(button)
        actions = ActionChains(drv)
        actions.w3c_actions.pointer_action.move_to_location(int(x), int(y))
        actions.w3c_actions.pointer_action.pointer_up(btn)
        actions.perform()
        return {"x": int(x), "y": int(y), "button": button.lower()}

    @capability("vision")
    def browser_mouse_drag_xy(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        button: Literal["left", "middle", "right"] = "left",
    ) -> dict[str, Any]:
        """Press ``button`` at ``(start_x, start_y)``, drag to
        ``(end_x, end_y)``, and release.
        """

        drv = self._require_driver()
        btn = _resolve_button(button)
        actions = ActionChains(drv)
        actions.w3c_actions.pointer_action.move_to_location(int(start_x), int(start_y))
        actions.w3c_actions.pointer_action.pointer_down(btn)
        actions.w3c_actions.pointer_action.move_to_location(int(end_x), int(end_y))
        actions.w3c_actions.pointer_action.pointer_up(btn)
        actions.perform()
        return {
            "start_x": int(start_x),
            "start_y": int(start_y),
            "end_x": int(end_x),
            "end_y": int(end_y),
            "button": button.lower(),
        }

    @capability("vision")
    def browser_mouse_wheel(
        self, delta_x: int, delta_y: int
    ) -> dict[str, Any]:
        """Scroll the mouse wheel by ``(delta_x, delta_y)`` pixels.

        Positive ``delta_y`` scrolls down; positive ``delta_x`` scrolls
        right. The pointer is moved to the viewport centre first because
        Firefox/geckodriver only dispatches W3C wheel events when the
        pointer lies over a hit-target; a freshly-created ``ActionChains``
        starts at viewport ``(0, 0)`` which Firefox treats as outside the
        document and silently drops the wheel.
        """

        drv = self._require_driver()
        size = drv.get_window_size()
        cx = int(size.get("width", 800)) // 2
        cy = int(size.get("height", 600)) // 2
        actions = ActionChains(drv)
        actions.w3c_actions.pointer_action.move_to_location(cx, cy)
        actions.scroll_by_amount(int(delta_x), int(delta_y))
        actions.perform()
        return {"delta_x": int(delta_x), "delta_y": int(delta_y)}

    @capability("vision")
    def browser_resize(self, width: int, height: int) -> dict[str, Any]:
        """Resize the browser window to ``width x height`` CSS pixels."""

        drv = self._require_driver()
        drv.set_window_size(int(width), int(height))
        return {"width": int(width), "height": int(height)}
