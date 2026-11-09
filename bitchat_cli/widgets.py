"""Reusable Textual widgets for the bitchat TUI."""
from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Input, RichLog, Static

from . import palette, theme


class BrandingPanel(Static):
    def __init__(self, version: str = "0.3.0", **kwargs):
        super().__init__(**kwargs)
        self.version = version

    def render(self):
        t = Text(no_wrap=True, overflow="crop")
        lines = theme._LOGO.strip("\n").splitlines()
        logo_w = max(len(ln) for ln in lines)
        sub = f"C L I  •  v{self.version}"
        if self.size.width >= logo_w:
            t.append("\n".join(lines) + "\n", style=f"bold {palette.EMERALD}")
            t.append(sub.center(logo_w), style=palette.MUTED)
        else:
            # Compact wordmark for narrow terminals (no wrapping/clipping).
            t.append("B I T C H A T\n", style=f"bold {palette.EMERALD}")
            t.append(sub, style=palette.MUTED)
        return t


class ConnectionInfo(Static):
    """Full connection block (wide terminals)."""

    def update_info(self, peer_mac: str, peer_id: str, sessions: int, uptime: str) -> None:
        connected = peer_mac not in ("—", "", None)
        t = Text()
        if connected:
            t.append("●  ", style=palette.EMERALD)
            t.append("Connected to: ", style=palette.EMERALD)
            t.append(f"{peer_mac}\n", style=palette.TEXT)
        else:
            t.append("●  ", style=palette.RED)
            t.append("Disconnected\n", style=palette.RED)
        for icon, label, value, last in (
            ("📡", "Peer: ", peer_id, False),
            ("👥", "Sessions: ", str(sessions), False),
            ("🕒", "Uptime: ", uptime, True),
        ):
            t.append(f"{icon} ")
            t.append(label, style=palette.MUTED)
            t.append(value + ("" if last else "\n"), style=palette.TEXT)
        self.update(t)


class ConnectionLine(Static):
    """Condensed one-line connection summary (shown when the full block is hidden)."""

    def update_info(self, peer_mac: str, peer_id: str, sessions: int, uptime: str) -> None:
        connected = peer_mac not in ("—", "", None)
        t = Text(no_wrap=True, overflow="ellipsis")
        t.append("● ", style=palette.EMERALD if connected else palette.RED)
        if connected:
            t.append(f"{peer_mac}", style=palette.TEXT)
        else:
            t.append("Disconnected", style=palette.RED)
        sep = ("  │  ", palette.MUTED)
        t.append(*sep)
        t.append("Peer ", style=palette.MUTED)
        t.append(peer_id, style=palette.TEXT)
        t.append(*sep)
        t.append("Sessions ", style=palette.MUTED)
        t.append(str(sessions), style=palette.TEXT)
        t.append(*sep)
        t.append("Up ", style=palette.MUTED)
        t.append(uptime, style=palette.TEXT)
        self.update(t)


class NetworkStatusPanel(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Network Status", id="net-title")
        yield Static("", id="net-body")

    def update_status(self, label: str, status: str, peers: int, rng: str = "Local") -> None:
        online = status == "Online"
        t = Text()
        t.append(f"{label}: ", style=palette.TEXT)
        t.append(status + "\n", style=f"bold {palette.EMERALD if online else palette.RED}")
        t.append("Peers: ", style=palette.TEXT)
        t.append(str(peers) + "\n", style=f"bold {palette.EMERALD}")
        t.append("Range: ", style=palette.TEXT)
        t.append(rng, style=palette.TEXT)
        try:
            self.query_one("#net-body", Static).update(t)
        except Exception:
            pass


class AppHeader(Horizontal):
    def __init__(self, version: str = "0.3.0", **kwargs):
        super().__init__(**kwargs)
        self.version = version

    def compose(self) -> ComposeResult:
        yield BrandingPanel(self.version, id="branding")
        yield ConnectionInfo(id="conn-info")
        yield NetworkStatusPanel(id="net-status")


class RoomHeader(Horizontal):
    def __init__(self, room: str = "# General", **kwargs):
        super().__init__(**kwargs)
        self.room = room

    def compose(self) -> ComposeResult:
        yield Static(f"👥 {self.room}", id="room-name")
        yield Static("|", id="room-sep")
        yield Static("1 online", id="room-online")
        yield Static("", id="room-spacer")
        yield Static(Text("[ ↑/↓ to navigate ]", style=palette.MUTED), id="room-hint")


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
    def compose(self) -> ComposeResult:
        for key, label in (("F1", "Help"), ("F2", "Peers"), ("F3", "Clear"), ("F4", "Settings")):
            yield KeyHint(key, label)
        yield Static("│", id="footer-div")
        yield Static(self._status_text(1), id="footer-status")
        yield Static("", id="footer-spacer")
        yield KeyHint("Ctrl+Q", "Quit")

    @staticmethod
    def _status_text(online: int, rooms: int = 1) -> Text:
        return Text.assemble(
            ("▲ ", palette.EMERALD),
            (f"{online} online", f"bold {palette.EMERALD}"),
            (" • ", palette.MUTED),
            (f"{rooms} room", palette.MUTED),
        )

    def update_footer(self, online: int, rooms: int = 1) -> None:
        try:
            self.query_one("#footer-status", Static).update(self._status_text(online, rooms))
        except Exception:
            pass
