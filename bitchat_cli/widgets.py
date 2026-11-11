"""Reusable Textual widgets for the bitchat TUI."""

from __future__ import annotations

from rich.color import Color
from rich.style import Style
from rich.text import Span, Text
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


def _status_glyph(state):
    """Tick glyph and colour for an outgoing DM state (None = no glyph).

    Colours come from the active theme (palette.colors()), so the ticks restyle
    with Ctrl+P > Change theme.
    """
    c = palette.colors()
    return {
        "sending": ("...", c["muted"]),
        "sent": ("\u2713", c["muted"]),
        "delivered": ("\u2713\u2713", c["muted"]),
        "read": ("\u2713\u2713", c["emerald"]),
        "failed": ("!", c["red"]),
        "unconfirmed": ("!", c["red"]),
    }.get(state)


def _recolor(text: Text, mapping: dict) -> Text:
    """Copy a Rich Text, replacing default-palette colours with the active ones.

    Chat lines are stored as ANSI strings built from the default palette, so a
    theme switch re-colours existing lines by mapping each default colour to
    its counterpart in the active theme.
    """
    if not mapping:
        return text
    out = text.copy()
    out.spans = [
        Span(span.start, span.end, _mapped_style(span.style, mapping))
        for span in text.spans
    ]
    return out


def _mapped_style(style, mapping: dict):
    if style is None or getattr(style, "color", None) is None:
        return style
    rgb = style.color.get_truecolor()
    if rgb not in mapping:
        return style
    return Style(bold=style.bold, italic=style.italic, underline=style.underline,
                 color=Color.parse(mapping[rgb]))


class ConversationView(RichLog):
    """A RichLog that keeps its entries so outgoing DM lines can re-render their status.

    Entries are (line, msg_id, is_self, state). A status change clears the log and
    rewrites every entry, so the glyph on a line updates in place. Capped at
    MAX_ENTRIES; the oldest are dropped. Writes while the tab has no width (a
    hidden background tab) are queued and replayed once the tab is sized.
    """

    MAX_ENTRIES = 1000

    def __init__(self, **kwargs):
        # min_width=0: the default (78) forces content wider than a 76-column pane at
        # 80x24, producing a horizontal scrollbar.
        super().__init__(highlight=False, markup=False, wrap=True, auto_scroll=False,
                         min_width=0, **kwargs)
        self._queued: list[tuple] = []
        self._entries: list[dict] = []

    def write(self, content, **kwargs):
        if self.region.width == 0:
            self._queued.append((content, kwargs))
            return self
        return super().write(content, **kwargs)

    def clear(self):
        self._entries.clear()
        self._queued.clear()
        return super().clear()

    def on_resize(self, event) -> None:
        # Replay lines written while this tab had no width (see write()).
        super().on_resize(event)
        if self._queued and self.region.width:
            queued, self._queued = self._queued, []
            for content, kwargs in queued:
                super().write(content, **kwargs)

    def add_entry(self, line: str, msg_id: str | None = None, is_self: bool = False,
                  state: str | None = None) -> None:
        self._entries.append({"line": line, "msg_id": msg_id, "is_self": is_self, "state": state})
        if len(self._entries) > self.MAX_ENTRIES:
            del self._entries[: len(self._entries) - self.MAX_ENTRIES]
            self._rerender()
            return
        self.write(self._render(self._entries[-1]), expand=True)

    def set_state(self, msg_id: str, state: str) -> bool:
        """Update the status of an outgoing line and re-render. True if a line matched."""
        hit = False
        for e in self._entries:
            if e["is_self"] and e["msg_id"] == msg_id:
                e["state"] = state
                hit = True
        if hit:
            at_bottom = self.scroll_offset.y >= self.max_scroll_y
            self._rerender()
            if at_bottom:
                self.scroll_end(animate=False)
        return hit

    def _render(self, entry: dict) -> Text:
        text = Text.from_ansi(str(entry["line"]))
        text = _recolor(text, palette.recolor_map())
        glyph = _status_glyph(entry["state"]) if entry["is_self"] else None
        if glyph is not None:
            text.append("  ")
            text.append(glyph[0], style=glyph[1])
        return text

    def rerender(self) -> None:
        """Re-draw every entry with the current theme colours."""
        self._rerender()

    def _rerender(self) -> None:
        self._queued.clear()
        RichLog.clear(self)
        for e in self._entries:
            self.write(self._render(e), expand=True)


class InputPanel(Horizontal):
    def compose(self) -> ComposeResult:
        c = palette.colors()
        yield Static(">", id="input-prompt")
        yield Input(placeholder="Type a message...", id="input")
        hint = Text.assemble(("[Enter]", f"bold {c['emerald']}"), (" Send", c["muted"]))
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
        c = palette.colors()
        yield KeyCap(Text(self._key, style=f"bold {c['emerald']}"), classes="keycap")
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
