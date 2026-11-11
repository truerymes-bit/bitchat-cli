"""Textual presentation layer for bitchat-cli (Stage 4: design system widgets)."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

os.environ.setdefault("BITCHAT_FORCE_COLOR", "1")

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.binding import Binding
from textual.widgets import Input, Static, Tabs, Tab, ContentSwitcher

from . import palette, theme
from .ble_service import BLEService
from .debuglog import dlog
from .chat_state import ChatState
from .cli import CLI
from .events import AppEvent, EventBus, EventType, GENERAL
from .screens import SettingsScreen
from .widgets import (
    AppFooter,
    AppHeader,
    ConversationView,
    InputPanel,
    RoomHeader,
)


class BitchatApp(App):
    CSS_PATH = Path(__file__).with_name("app.tcss")

    # Key map. No single-letter bindings. ctrl+q is Textual's own quit; ctrl+c is
    # left to copy (Screen/Input). F1-F4 are unbound in Textual, Input, RichLog
    # and ghostty's default keybinds.
    # ctrl+w is a priority binding: the Input widget binds it to delete_left_word,
    # and priority bindings are checked from the app down, so the tab still closes
    # while the input has focus.
    BINDINGS = [
        Binding("f1", "show_help", "Help"),
        Binding("f2", "show_peers", "Peers"),
        Binding("f3", "clear_chat", "Clear"),
        Binding("f4", "show_settings", "Settings"),
        Binding("alt+left", "prev_tab", "Previous tab", show=False),
        Binding("alt+right", "next_tab", "Next tab", show=False),
        Binding("ctrl+w", "close_tab", "Close tab", show=False, priority=True),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def get_css_variables(self) -> dict:
        variables = super().get_css_variables()
        variables.update(palette.css_variables())
        return variables

    def __init__(self, state: ChatState, log=None):
        super().__init__()
        self.state = state
        self.event_bus = EventBus()
        self.ble_service = BLEService(state, self._request_redraw, log=log or dlog)
        self.cli = CLI(state)
        self.cli.ble_service = self.ble_service
        self.ble_service.dm_visible = self._dm_visible
        self.ble_service.dm_status_cb = self._publish_dm_status
        self.cli._out = lambda line, conv=None: self.event_bus.publish_nowait(
            AppEvent(EventType.OUTPUT, line, conv)
        )
        self.cli.redraw_prompt = self._request_redraw
        self.cli.clear_screen = self.action_clear_chat
        self.cli.open_dm = self.open_dm
        self.ble_service._emit = lambda line, conv=None, msg_id=None, is_self=False: self.event_bus.publish_nowait(
            AppEvent(EventType.OUTPUT, line, conv, msg_id=msg_id, is_self=is_self)
        )

        # Conversation key -> (ConversationView, unread count). Closed DM tabs
        # keep their view here so history survives the session.
        self.conversations: dict[str, tuple[ConversationView, int]] = {}
        self._current_conv = GENERAL

    # ------------------------------------------------------------------ #
    # Conversation / tab management
    # ------------------------------------------------------------------ #
    @staticmethod
    def _tab_id(key: str) -> str:
        return f"tab-{key}"

    @staticmethod
    def _view_id(key: str) -> str:
        return f"conv-{key}"

    def _label_for(self, key: str) -> str:
        if key == GENERAL:
            return "# General"
        nick = self.state.peer_nicknames.get(key)
        return f"@{nick}" if nick else f"@{key[:8]}"

    def _ensure_view(self, key: str, set_current: bool = False) -> None:
        if key in self.conversations:
            return
        view = ConversationView(id=self._view_id(key))
        switcher = self.query_one("#conversation-switcher", ContentSwitcher)
        view.display = False
        self.conversations[key] = (view, 0)
        switcher.mount(view)
        if set_current:
            switcher.current = view.id

    def _ensure_tab(self, key: str) -> None:
        tab_id = self._tab_id(key)
        tabs = self.query_one("#conv-tabs", Tabs)
        if tabs.get_tab(tab_id) is not None:
            return
        tabs.add_tab(Tab(self._label_for(key), id=tab_id))

    def _ensure_conv(self, key: str) -> None:
        self._ensure_view(key)
        self._ensure_tab(key)

    def _set_tab_label(self, key: str, unread: int | None = None) -> None:
        entry = self.conversations.get(key)
        if entry is None:
            return
        if unread is None:
            unread = entry[1]
        label = self._label_for(key)
        if unread:
            label = f"{label} ({unread})"
        try:
            self.query_one(f"#{self._tab_id(key)}", Tab).label = label
        except Exception:
            pass

    def _refresh_tabs(self) -> None:
        for key in list(self.conversations):
            self._set_tab_label(key)

    def _open_keys(self) -> list[str]:
        """Keys of the currently open tabs, in display order."""
        try:
            tabs = self.query_one("#conv-tabs", Tabs)
        except Exception:
            return []
        keys = []
        for tab in tabs.query(Tab):
            tab_id = tab.id or ""
            if tab_id.startswith("tab-"):
                keys.append(tab_id[len("tab-"):])
        return keys

    def _dm_visible(self, peer_id_hex: str) -> bool:
        # A DM counts as read only while its tab is shown and the app has focus.
        return self._current_conv == peer_id_hex and self.app_focus

    def _switch_conv(self, key: str) -> None:
        if key not in self.conversations:
            self._ensure_conv(key)
        self._current_conv = key
        if key != GENERAL:
            # Activating a DM tab sends a read receipt for each unread incoming message.
            self.run_worker(self.ble_service.read_receipts_for_peer(key))
        try:
            tabs = self.query_one("#conv-tabs", Tabs)
            if tabs.get_tab(self._tab_id(key)) is not None:
                tabs.active = self._tab_id(key)
        except Exception:
            pass
        try:
            switcher = self.query_one("#conversation-switcher", ContentSwitcher)
            if switcher.get_child_by_id(self._view_id(key)) is not None:
                switcher.current = self._view_id(key)
        except Exception:
            pass
        self._clear_unread(key)
        self._update_room_header()
        try:
            self.query_one("#input", Input).focus()
        except Exception:
            pass

    def _clear_unread(self, key: str) -> None:
        entry = self.conversations.get(key)
        if entry is None or not entry[1]:
            return
        self.conversations[key] = (entry[0], 0)
        self._set_tab_label(key, 0)

    def _bump_unread(self, key: str) -> None:
        entry = self.conversations.get(key)
        if entry is None:
            return
        unread = entry[1] + 1
        self.conversations[key] = (entry[0], unread)
        self._set_tab_label(key, unread)

    def open_dm(self, peer_id_hex: str, switch: bool = True) -> None:
        """Create or restore a DM tab; `switch=True` also activates it."""
        key = (peer_id_hex or "").lower()
        if not key:
            return
        self._ensure_view(key)
        self._ensure_tab(key)
        if switch:
            self._switch_conv(key)

    def _move_tab(self, delta: int) -> None:
        keys = self._open_keys()
        if not keys:
            return
        try:
            index = keys.index(self._current_conv)
        except ValueError:
            index = 0
        self._switch_conv(keys[(index + delta) % len(keys)])

    def action_prev_tab(self) -> None:
        self._move_tab(-1)

    def action_next_tab(self) -> None:
        self._move_tab(+1)

    def action_close_tab(self) -> None:
        key = self._current_conv
        if key == GENERAL:
            return
        # Switch away first so the removed tab is not the active one (Tabs would
        # otherwise auto-activate a neighbour and post its own TabActivated).
        self._switch_conv(GENERAL)
        try:
            self.query_one("#conv-tabs", Tabs).remove_tab(self._tab_id(key))
        except Exception:
            pass

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        tab_id = event.tab.id or ""
        if not tab_id.startswith("tab-"):
            return
        key = tab_id[len("tab-"):]
        if key == self._current_conv:
            return
        self._switch_conv(key)

    def _update_room_header(self) -> None:
        try:
            room = self.query_one("#room-header", RoomHeader)
        except Exception:
            return
        key = self._current_conv
        if key == GENERAL:
            room.update_room("# General", f"{len(self.state.peer_nicknames) + 1} online")
            return
        nick = self.state.peer_nicknames.get(key)
        status = "online" if key in self.state.peer_nicknames else "offline"
        room.update_room(f"@{nick}" if nick else f"@{key[:8]}", status)

    def compose(self) -> ComposeResult:
        yield AppHeader(id="app-header")
        with Vertical(id="conversation"):
            yield RoomHeader(id="room-header")
            yield ContentSwitcher(id="conversation-switcher")
        yield InputPanel(id="input-panel")
        yield AppFooter(id="footer")

    async def on_mount(self) -> None:
        self.query_one("#input", Input).focus()
        self._ble_task = asyncio.ensure_future(self.ble_service.run())
        self._consumer_task = asyncio.ensure_future(self._consume_events())
        self._status_task = asyncio.ensure_future(self._status_loop())
        self._apply_responsive(self.size.width)
        self._ensure_view(GENERAL, set_current=True)
        self._ensure_tab(GENERAL)
        self._switch_conv(GENERAL)
        self._refresh_status()

    async def action_show_help(self) -> None:
        await self.cli.handle_command("/help")

    async def action_show_peers(self) -> None:
        await self.cli.handle_command("/peers")

    def action_clear_chat(self) -> None:
        # Display only: ChatState.messages and all network state are untouched.
        entry = self.conversations.get(self._current_conv)
        if entry is not None:
            entry[0].clear()

    def action_show_settings(self) -> None:
        self.push_screen(
            SettingsScreen(self.state.nickname, self.state.my_peer_id_hex),
            self._apply_settings,
        )

    async def _apply_settings(self, nickname) -> None:
        # Reuses the existing /name path (persists nickname + re-announces).
        if nickname and nickname != self.state.nickname:
            await self.cli.handle_command(f"/name {nickname}")

    def on_resize(self, event) -> None:
        self._apply_responsive(event.size.width)

    def _apply_responsive(self, width: int) -> None:
        # Breakpoints live in app.tcss as Screen classes; no inline sizing here.
        self.screen.set_class(width >= 120, "-wide")
        self.screen.set_class(100 <= width < 120, "-medium")
        self.screen.set_class(80 <= width < 100, "-narrow")
        self.screen.set_class(width < 80, "-tiny")

    async def on_unmount(self) -> None:
        for t in (getattr(self, "_ble_task", None),
                  getattr(self, "_consumer_task", None),
                  getattr(self, "_status_task", None)):
            if t is not None:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        try:
            await self.ble_service.stop()
        except Exception:
            pass

    def _request_redraw(self) -> None:
        self.event_bus.publish_nowait(AppEvent(EventType.STATUS))

    async def _consume_events(self) -> None:
        while True:
            ev = await self.event_bus.get()
            if ev.type == EventType.OUTPUT:
                self._append_line(ev.payload, ev.conv, ev.msg_id, ev.is_self)
            elif ev.type == EventType.DM_STATUS:
                self._on_dm_status(ev.payload)
            elif ev.type == EventType.STATUS:
                self._refresh_status()

    async def _status_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            self.event_bus.publish_nowait(AppEvent(EventType.STATUS))

    def _refresh_status(self) -> None:
        try:
            header = self.query_one(AppHeader)
        except Exception:
            return
        st = self.state
        # Link state: a dot plus one word (Connected / Searching / Offline).
        # Use the existing state: ble_service._running and state.connected_addresses
        # / direct_peers. Connected means at least one connected peer.
        if self.ble_service._running:
            if st.connected_addresses or st.direct_peers:
                col = palette.EMERALD
                label = "Connected"
            else:
                col = palette.MUTED
                label = "Searching"
        else:
            col = palette.RED
            label = "Offline"
        header.update_link("●", col, label, col)
        self._update_room_header()
        self._refresh_tabs()

    def _append_line(self, line: str, conv: str | None = None, msg_id: str | None = None,
                     is_self: bool = False) -> None:
        key = conv if conv is not None else self._current_conv
        if key != GENERAL and key not in self.conversations:
            # A DM from a peer with no tab yet: create it, do not steal focus.
            self._ensure_conv(key)
        entry = self.conversations.get(key)
        if entry is None:
            return
        view = entry[0]
        at_bottom = view.scroll_offset.y >= view.max_scroll_y
        # Outgoing DM lines carry a status glyph: they start as "sending".
        view.add_entry(str(line), msg_id=msg_id, is_self=is_self,
                       state="sending" if (is_self and msg_id) else None)
        if at_bottom:
            view.scroll_end(animate=False)
        if key != self._current_conv:
            self._bump_unread(key)

    def _publish_dm_status(self, conv: str, msg_id: str, state: str) -> None:
        self.event_bus.publish_nowait(AppEvent(EventType.DM_STATUS, {
            "conv": conv, "msg_id": msg_id, "state": state}))

    def _on_dm_status(self, payload: dict) -> None:
        entry = self.conversations.get(payload["conv"])
        if entry is not None:
            entry[0].set_state(payload["msg_id"], payload["state"])

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "input":
            return
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return
        if text.startswith("/"):
            if self._current_conv != GENERAL:
                cmd = text.split(" ", 1)[0].lower()
                if cmd in ("/send", "/file"):
                    self._append_line(theme.warn(
                        "File DMs are not supported yet. "
                        "Switch to General to broadcast a file."
                    ))
                    return
            await self.cli.handle_command(text)
            return
        key = self._current_conv
        if key == GENERAL:
            self.run_worker(self.ble_service.send_public_message(text))
            return
        if key not in self.state.peer_info:
            self._append_line(theme.warn(
                f"Cannot DM {key[:8]}: no Noise key known for that peer yet."
            ))
            return
        self.run_worker(self.ble_service.send_private_message(key, text))
