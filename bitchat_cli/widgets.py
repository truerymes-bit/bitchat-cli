"""Reusable Textual widgets for the bitchat TUI."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, RichLog, Static

from . import palette


class AppHeader(Horizontal):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Static("B I T C H A T", id="wordmark")
        with Horizontal():
            yield Static("●", id="link-dot")
            yield Static("Offline", id="link-state")

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
        self.online = online

    def compose(self) -> ComposeResult:
        yield Static(f"{self.room} · {self.online} online", id="room-online")

    def update_online(self, online: int) -> None:
        try:
            self.query_one("#room-online", Static).update(f"{self.room} · {online} online")
        except Exception:
            pass


class ConversationView(RichLog):
    def __init__(self, **kwargs):
        # min_width=0: the default (78) forces content wider than a 76-column pane at
        # 80x24, producing a horizontal scrollbar.
        super().__init__(highlight=False, markup=False, wrap=True, auto_scroll=False,
                         min_width=0, **kwargs)


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
