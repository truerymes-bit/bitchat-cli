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
from textual.widgets import Input, Static

from .ble_service import BLEService
from .chat_state import ChatState
from .cli import CLI
from .events import AppEvent, EventBus, EventType
from .screens import SettingsScreen
from .widgets import (
    AppFooter,
    AppHeader,
    ConversationView,
    InputPanel,
    RoomHeader,
)
from . import palette, theme


class BitchatApp(App):
    CSS_PATH = Path(__file__).with_name("app.tcss")

    # Key map. No single-letter bindings. ctrl+q is Textual's own quit; ctrl+c is
    # left to copy (Screen/Input). F1-F4 are unbound in Textual, Input, RichLog
    # and ghostty's default keybinds.
    BINDINGS = [
        Binding("f1", "show_help", "Help"),
        Binding("f2", "show_peers", "Peers"),
        Binding("f3", "clear_chat", "Clear"),
        Binding("f4", "show_settings", "Settings"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def get_css_variables(self) -> dict:
        variables = super().get_css_variables()
        variables.update(palette.css_variables())
        return variables

    def __init__(self, state: ChatState):
        super().__init__()
        self.state = state
        self.event_bus = EventBus()
        self.ble_service = BLEService(state, self._request_redraw)
        self.cli = CLI(state)
        self.cli.ble_service = self.ble_service
        self.cli._out = lambda line: self.event_bus.publish_nowait(
            AppEvent(EventType.OUTPUT, line)
        )
        self.cli.redraw_prompt = self._request_redraw
        self.cli.clear_screen = self.action_clear_chat
        self.ble_service._emit = lambda line: self.event_bus.publish_nowait(
            AppEvent(EventType.OUTPUT, line)
        )

    def compose(self) -> ComposeResult:
        yield AppHeader(id="app-header")
        with Vertical(id="conversation"):
            yield RoomHeader(id="room-header")
            yield ConversationView(id="chat")
        yield InputPanel(id="input-panel")
        yield AppFooter(id="footer")

    async def on_mount(self) -> None:
        self.query_one("#input", Input).focus()
        self._ble_task = asyncio.ensure_future(self.ble_service.run())
        self._consumer_task = asyncio.ensure_future(self._consume_events())
        self._status_task = asyncio.ensure_future(self._status_loop())
        self._apply_responsive(self.size.width)
        self._refresh_status()

    async def action_show_help(self) -> None:
        await self.cli.handle_command("/help")

    async def action_show_peers(self) -> None:
        await self.cli.handle_command("/peers")

    def action_clear_chat(self) -> None:
        # Display only: ChatState.messages and all network state are untouched.
        try:
            self.query_one("#chat", ConversationView).clear()
        except Exception:
            pass

    def action_show_settings(self) -> None:
        self.push_screen(SettingsScreen(self.state.nickname), self._apply_settings)

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
                self._append_line(ev.payload)
            elif ev.type == EventType.STATUS:
                self._refresh_status()

    async def _status_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            self.event_bus.publish_nowait(AppEvent(EventType.STATUS))

    def _refresh_status(self) -> None:
        try:
            header = self.query_one(AppHeader)
            room = self.query_one("#room-header", RoomHeader)
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
        # Room-header online count (counts me).
        room.update_online(len(st.peer_nicknames) + 1)

    def _append_line(self, line: str) -> None:
        try:
            log = self.query_one("#chat", ConversationView)
        except Exception:
            return
        at_bottom = log.scroll_offset.y >= log.max_scroll_y
        log.write(Text.from_ansi(str(line)), expand=True)
        if at_bottom:
            log.scroll_end(animate=False)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "input":
            return
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return
        if text.startswith("/"):
            await self.cli.handle_command(text)
        else:
            await self.ble_service.send_public_message(text)
