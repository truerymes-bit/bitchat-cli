"""Modal screens for the bitchat TUI."""
from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from . import palette


class SettingsScreen(ModalScreen):
    """Minimal settings: change nickname. Applying reuses the existing /name path."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, nickname: str):
        super().__init__()
        self._nickname = nickname

    def compose(self) -> ComposeResult:
        with Vertical(id="settings-box"):
            yield Static("Settings", id="settings-title")
            yield Static("Nickname", id="settings-label")
            yield Input(value=self._nickname, id="settings-nick")
            yield Static(f"Your ID: <{self.state.my_peer_id_hex}>", id="settings-id")
            yield Static(
                Text.assemble(
                    ("[Enter]", f"bold {palette.EMERALD}"), (" Apply   ", palette.MUTED),
                    ("[Esc]", f"bold {palette.EMERALD}"), (" Cancel", palette.MUTED),
                ),
                id="settings-hint",
            )

    def on_mount(self) -> None:
        self.query_one("#settings-nick", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()  # do not let the main chat handler see this submit
        self.dismiss(event.value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)
