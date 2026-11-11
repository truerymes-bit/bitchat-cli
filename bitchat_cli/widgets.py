"""Reusable Textual widgets for the bitchat TUI."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Input, RichLog, Static, Tab, Tabs

from . import palette


class AppHeader(Vertical):
    """Brand row, conversation tabs and the link indicator."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        with Horizontal(id="header-top"):
            yield Static("B I T C H A T", id="wordmark")
            with Horizontal(id="link-container"):
                yield Static("●", id="link-dot")
                yield Static("Offline", id="link-state")
        yield Tabs(id="conv-tabs")

    def update_link(self, dot: str, dot_color: str, label: str, label_color: str) -> None:
        try:
            self.query_one("#link-dot", Static).update(Text(dot, style=dot_color))
            self.query_one("#link-state", Static).update(Text(label, style=label_color))
        except Exception:
            pass


class RoomHeader(Horizontal):
    def __init__(self, room: str = "# General", online: int = 1, **kwargs):
        super().__init__(**kwargs)
        self.room = room
        self._status = f"{online} online"

    def compose(self) -> ComposeResult:
        yield Static(self._text(), id="room-online")

    def _text(self) -> str:
        return f"{self.room} · {self._status}"

    def update_online(self, online: int) -> None:
        self._status = f"{online} online"
        self._push()

    def update_room(self, room: str, status: str) -> None:
        self.room = room
        self._status = status
        self._push()

    def _push(self) -> None:
        try:
            self.query_one("#room-online", Static).update(self._text())
        except Exception:
            pass


class ConversationView(RichLog):
    """A RichLog that accepts writes while it is hidden (a background tab).

    RichLog renders at its own width; a hidden tab has none, so a line written
    then would come out blank. Queue those lines and replay them once the tab
    has been given a size.
    """

    def __init__(self, **kwargs):
        # min_width=0: the default (78) forces content wider than a 76-column pane at
        # 80x24, producing a horizontal scrollbar.
        super().__init__(highlight=False, markup=False, wrap=True, auto_scroll=False,
                         min_width=0, **kwargs)
        self._queued: list[tuple] = []

    def write(self, content, **kwargs):
        if self.region.width == 0:
            self._queued.append((content, kwargs))
            return self
        return super().write(content, **kwargs)

    def clear(self):
        self._queued.clear()
        return super().clear()

    def on_resize(self, event) -> None:
        super().on_resize(event)
        if self._queued and self.region.width:
            queued, self._queued = self._queued, []
            for content, kwargs in queued:
                super().write(content, **kwargs)


class InputPanel(Horizontal):
    def compose(self) -> ComposeResult:
        yield Static(">", id="input-prompt")
        yield Input(placeholder="Type a message...", id="input")
        hint = Text.assemble(("[Enter]", f"bold {palette.EMERALD}"), (" Send", palette.MUTED))
        yield Static(hint, id="input-hint")


class KeyCap(Static):
    """The boxed key label, e.g. F1."""


class KeyHint(Horizontal):
    """A key cap with its description beside it."""

    def __init__(self, key: str, label: str, **kwargs):
        super().__init__(**kwargs)
        self._key = key
        self._label = label

    def compose(self) -> ComposeResult:
        yield KeyCap(Text(self._key, style=f"bold {palette.EMERALD}"), classes="keycap")
        yield Static(self._label, classes="keylabel")


class AppFooter(Horizontal):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._keys = (
            ("F1", "Help"),
            ("F2", "Peers"),
            ("F3", "Clear"),
            ("F4", "Settings"),
            ("Ctrl+Q", "Quit"),
        )

    def compose(self) -> ComposeResult:
        for idx, (key, label) in enumerate(self._keys):
            if key == "Ctrl+Q":
                yield Static("", classes="footer-spacer")
            yield KeyHint(key=key, label=label)
