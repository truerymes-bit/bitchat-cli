"""Modal screens for the bitchat TUI."""
from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import OptionList
from textual.widgets.option_list import Option
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from . import palette


class SettingsScreen(ModalScreen):
    """Minimal settings: change nickname. Applying reuses the existing /name path."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, nickname: str, peer_id: str):
        super().__init__()
        self._nickname = nickname
        self._peer_id = peer_id

    def compose(self) -> ComposeResult:
        with Vertical(id="settings-box"):
            yield Static("Settings", id="settings-title")
            yield Static("Nickname", id="settings-label")
            yield Input(value=self._nickname, id="settings-nick")
            yield Static(f"Your ID: <{self._peer_id}>", id="settings-id")
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

VERIFIED_TICK = "\u2713"   # single-cell tick, terminal-safe
DM_LOCK = "L"          # narrow single-cell session glyph


def peer_glyphs(state, ble_service, peer_id):
    """(verified_glyph, session_glyph) for a peer row; each '' when absent."""
    tick = VERIFIED_TICK if state.is_verified(peer_id) else ""
    lock = ""
    sess = ble_service._noise_sessions.get(peer_id)
    if sess is not None and sess.is_finished:
        lock = DM_LOCK
    return tick, lock


def peer_row(state, ble_service, peer_id, nick, is_me=False):
    """(option_id, prompt, disabled) for one peer row: two glyph cells then the nickname."""
    tick, lock = ("", "") if is_me else peer_glyphs(state, ble_service, peer_id)
    glyphs = f"{tick:<1} {lock:<1} " if not is_me else ""
    if is_me:
        prompt = f"{glyphs}{nick} (you)"
    elif peer_id not in state.peer_info:
        prompt = f"{glyphs}{nick} (no DM)"
    else:
        prompt = f"{glyphs}{nick}"
    disabled = False  # every row is selectable; Enter warns for me / no-DM peers
    return peer_id, prompt, disabled


class PeersScreen(ModalScreen):
    """F2: peer list. Enter opens a DM tab; v toggles verification."""

    BINDINGS = [Binding("escape", "close", "Close"),
                Binding("v", "toggle_verify", "Verify")]

    def __init__(self, state, ble_service, open_dm, notify):
        super().__init__()
        self._state = state
        self._ble = ble_service
        self._open_dm = open_dm
        self._notify = notify
        self._rows = []

    def compose(self) -> ComposeResult:
        with Vertical(id="peers-box"):
            yield Static("Peers", id="peers-title")
            yield OptionList(id="peers-list")
            yield Static("", id="peers-detail")

    def on_mount(self) -> None:
        self._load()
        self.query_one("#peers-list", OptionList).focus()

    def _load(self):
        """Rebuild the list. Called on mount and whenever the app status ticks."""
        st = self._state
        rows = [(st.my_peer_id_hex, f"{st.nickname} (you)", True)]
        for pid in sorted(st.peer_nicknames, key=lambda p: st.peer_nicknames[p].lower()):
            nick = st.peer_nicknames[pid]
            rows.append(peer_row(st, self._ble, pid, nick))
        self._rows = rows
        options = [Option(prompt, id=pid, disabled=disabled) for pid, prompt, disabled in rows]
        lst = self.query_one("#peers-list", OptionList)
        keep = lst.highlighted or 0
        lst.clear_options()
        lst.add_options(options)
        lst.highlighted = min(keep, len(options) - 1)
        self._show_detail()

    def _highlighted(self):
        lst = self.query_one("#peers-list", OptionList)
        idx = lst.highlighted
        return self._rows[idx] if idx is not None and 0 <= idx < len(self._rows) else None

    def _show_detail(self):
        row = self._highlighted()
        if row is None:
            return
        pid = row[0]
        if pid == self._state.my_peer_id_hex:
            detail = f"{self._state.nickname} (you)  id {pid[:8]}"
        elif pid not in self._state.peer_info:
            detail = f"{self._state.peer_nicknames.get(pid, pid[:8])}  id {pid[:8]}  no Noise key"
        else:
            from .cli import noise_fingerprint
            fp = noise_fingerprint(pid, self._state)
            detail = (f"{self._state.peer_nicknames.get(pid, pid[:8])}  id {pid[:8]}  "
                      f"fingerprint {fp}")
        self.query_one("#peers-detail", Static).update(detail)

    def on_option_list_highlighted(self, event) -> None:
        self._show_detail()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        # OptionList consumes Enter, so the screen binding never fires; use its message.
        self._show_detail()
        self.action_open_dm()

    def on_option_list_option_selected(self, event) -> None:
        # OptionList consumes Enter and emits this instead of the `enter` binding.
        self._open_highlighted()

    def _open_highlighted(self) -> None:
        row = self._highlighted()
        if row is None:
            return
        pid = row[0]
        if pid == self._state.my_peer_id_hex or pid not in self._state.peer_info:
            self._notify(f"{self._state.nickname_for(pid)} cannot be messaged yet",
                         severity="warning")
            return
        self._open_dm(pid, switch=True)
        self.dismiss()

    def on_option_list_option_selected(self, event) -> None:
        self.action_open_dm()

    def action_open_dm(self):
        row = self._highlighted()
        if row is None:
            return
        pid = row[0]
        if pid == self._state.my_peer_id_hex or pid not in self._state.peer_info:
            self._notify(f"{self._state.nickname_for(pid)} cannot be messaged yet",
                         severity="warning")
            return
        self._open_dm(pid, switch=True)
        self.dismiss()

    def action_toggle_verify(self):
        row = self._highlighted()
        if row is None:
            return
        pid = row[0]
        if pid == self._state.my_peer_id_hex or pid not in self._state.peer_info:
            self._notify(f"{self._state.nickname_for(pid)} cannot be messaged yet",
                         severity="warning")
            return
        if self._state.is_verified(pid):
            self._state.unverify_peer(pid)
            self._notify(f"Unverified {self._state.nickname_for(pid)}")
        else:
            self._state.verify_peer(pid)
            self._notify(f"Verified {self._state.nickname_for(pid)}")
        self._load()

    def action_close(self):
        self.dismiss()


class HelpScreen(ModalScreen):
    """F1: keys (from the app's BINDINGS) and slash commands (from cli.COMMANDS)."""

    BINDINGS = [Binding("escape", "close", "Close")]

    def __init__(self, key_bindings, commands):
        super().__init__()
        # Not self._bindings: that is Textual's BindingsMap for this screen.
        self._key_bindings = key_bindings
        self._commands = commands

    def compose(self) -> ComposeResult:
        from .cli import COMMANDS  # noqa: F401  (kept for parity with the table source)
        with VerticalScroll(id="help-box"):
            yield Static("Help", id="help-title")
            yield Static("Keys", id="help-keys-title")
            for b in self._key_bindings:
                if b.show:
                    # markup=False: "[msg]" in a command name must not be eaten as a tag.
                    yield Static(f"  {b.key:<10} {b.description}", classes="help-key",
                                 markup=False)
            yield Static("Commands", id="help-cmds-title")
            for name, desc in self._commands:
                yield Static(f"  {name:<22} {desc}", classes="help-cmd", markup=False)
            yield Static("[Esc] Close", id="help-hint", markup=False)

    def action_close(self):
        self.dismiss()


