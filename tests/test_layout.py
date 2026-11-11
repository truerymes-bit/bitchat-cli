"""Layout, tab and routing tests for BitchatApp (tabbed conversations).

Run with:  /usr/bin/python3 tests/test_layout.py
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from textual.widgets import Input, OptionList, Static, Tab, Tabs

from rich.color import Color

from bitchat_cli.app import BitchatApp
from bitchat_cli.events import AppEvent, EventType
from bitchat_cli import palette
from bitchat_cli import theme as theme_mod
from bitchat_cli.cli import COMMANDS
from bitchat_cli.events import GENERAL
from bitchat_cli.widgets import ConversationView
from bitchat_cli.chat_state import ChatState
from bitchat_cli.screens import SettingsScreen

FAKE_PEER = "a" * 16


def check(label, condition, detail=None):
    if not condition:
        raise AssertionError(f"{label}" + (f" -- {detail}" if detail is not None else ""))
FAKE_PEER2 = "b" * 16


async def _stub_run():
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass


def _make_app(nickname: str = "Tester"):
    state = ChatState(nickname=nickname)
    state.verified_peers = set()  # tests are independent of ~/.bitchat/verified_peers.json
    app = BitchatApp(state, log=[].append)  # debug lines to a list, never the real log
    # No BLE hardware in tests.
    app.ble_service.run = _stub_run  # type: ignore[assignment]
    app.ble_service.send_public_message = AsyncMock()  # type: ignore[assignment]
    app.ble_service.send_private_message = AsyncMock()  # type: ignore[assignment]
    app.ble_service.send_file = AsyncMock()  # type: ignore[assignment]
    app.ble_service.read_receipts_for_peer = AsyncMock()  # type: ignore[assignment]
    return app, state


def _add_peer(state: ChatState, peer_id: str, nick: str) -> None:
    state.peer_info[peer_id] = {
        "nickname": nick,
        "noise_public_key": b"k" * 32,
        "signing_public_key": b"s" * 32,
    }
    state.peer_nicknames[peer_id] = nick


def _view_text(view) -> str:
    return "".join(strip.text for strip in view.lines)


async def _submit(pilot, app: BitchatApp, text: str) -> None:
    app.query_one("#input", Input).focus()
    app.query_one("#input", Input).value = text
    await pilot.press("enter")
    await pilot.pause()
    await app.workers.wait_for_complete()
    await asyncio.sleep(0.05)


def _line_texts(view) -> list[str]:
    return [strip.text for strip in view.lines]


def _option_rows(modal):
    lst = modal.query_one("#peers-list", OptionList)
    return [(o.id, o.prompt.plain if hasattr(o.prompt, "plain") else str(o.prompt))
            for o in lst.options]


def _fake_session(svc, peer, finished=True):
    class _S:
        is_finished = finished
        created_at = svc.clock() if hasattr(svc, "clock") else 0.0
    svc._noise_sessions[peer] = _S()


async def _modal_scenario(size: tuple[int, int]) -> None:
    """F1/F2 modals: peers list, glyphs, Enter, verify toggle, help, no chat writes."""
    app, state = _make_app()
    from bitchat_cli.screens import PeersScreen, HelpScreen, VERIFIED_TICK, DM_LOCK
    # bob: verified + session; carol: verified only; dave: session only; erin: neither
    for pid, nick in ((FAKE_PEER, "bob"), (FAKE_PEER2, "carol")):
        _add_peer(state, pid, nick)
    dave, erin, nokey = "d" * 16, "e" * 16, "f" * 16
    _add_peer(state, dave, "dave"); _add_peer(state, erin, "erin")
    state.set_peer(nokey, "frank")  # nickname only, no Noise key
    state.verify_peer(FAKE_PEER); state.verify_peer(FAKE_PEER2)
    _fake_session(app.ble_service, FAKE_PEER)
    _fake_session(app.ble_service, dave)

    async with app.run_test(size=size) as pilot:
        await pilot.pause(); await asyncio.sleep(0.1)

        # ---- (a) F2 opens the modal; rows, order, glyphs
        await pilot.press("f2"); await pilot.pause(); await asyncio.sleep(0.1)
        assert isinstance(app.screen, PeersScreen), type(app.screen)
        rows = _option_rows(app.screen)
        check(f"{size} row count is peers + me", len(rows) == 6, len(rows))
        check(f"{size} me row is first", rows[0][1].endswith("(you)"), rows[0])
        check(f"{size} rows sorted by nickname",
              [r[1] for r in rows[1:]] == ["✓ L bob", "✓   carol", "  L dave", "    erin", "    frank (no DM)"],
              [r[1] for r in rows[1:]])
        box = app.screen.query_one("#peers-box")
        r = box.region
        check(f"{size} peers modal inside screen",
              r.width > 0 and r.height > 0 and r.right <= app.size.width and r.bottom <= app.size.height,
              r)
        app.save_screenshot(f"screenshot_peers_{size[0]}x{size[1]}.svg")

        # ---- (b) Enter on a DM-able peer opens and activates the tab
        before_tabs = app._open_keys()
        lst = app.screen.query_one("#peers-list", OptionList)
        lst.highlighted = next(i for i, (pid, _) in enumerate(_option_rows(app.screen)) if pid == FAKE_PEER)
        await pilot.press("enter"); await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} Enter on bob closes the modal", not isinstance(app.screen, PeersScreen))
        check(f"{size} bob tab added and active",
              FAKE_PEER in app._open_keys() and app._current_conv == FAKE_PEER)

        # Enter on "me" and on the no-DM peer: no tab, warning raised
        await pilot.press("f2"); await pilot.pause(); await asyncio.sleep(0.1)
        before = app._open_keys()
        app.screen.query_one("#peers-list", OptionList).highlighted = 0
        await pilot.press("enter"); await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} Enter on me adds no tab", app._open_keys() == before)
        lst = app.screen.query_one("#peers-list", OptionList)
        lst.highlighted = next(i for i, (pid, _) in enumerate(_option_rows(app.screen)) if pid == nokey)
        await pilot.press("enter"); await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} Enter on no-DM peer adds no tab", app._open_keys() == before)
        check(f"{size} warning notification raised",
              len(app._notifications._notifications) > 0, app._notifications._notifications)

        # ---- (c) v toggles verification
        lst = app.screen.query_one("#peers-list", OptionList)
        lst.highlighted = next(i for i, (pid, _) in enumerate(_option_rows(app.screen)) if pid == erin)
        await pilot.press("v"); await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} v verifies the highlighted peer", state.is_verified(erin))
        lst = app.screen.query_one("#peers-list", OptionList)
        erin_row = dict(_option_rows(app.screen))[erin]
        check(f"{size} verified row glyph shows the tick", erin_row.startswith(VERIFIED_TICK), erin_row)
        await pilot.press("v"); await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} v again un-verifies", not state.is_verified(erin))

        # ---- (d) a peer joining while the modal is open appears
        late = "9" * 16
        _add_peer(state, late, "zoe")
        app._refresh_peers_screen()
        await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} peer joining while open appears",
              late in dict(_option_rows(app.screen)))
        await pilot.press("escape"); await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} Esc closes the peers modal", not isinstance(app.screen, PeersScreen))

        # ---- (e) DM tab label and room header status
        app.open_dm(FAKE_PEER); await pilot.pause(); await asyncio.sleep(0.1)
        label = app.query_one(f"#tab-{FAKE_PEER}", Tab).label_text
        check(f"{size} DM tab label shows lock and tick",
              label.startswith(VERIFIED_TICK + DM_LOCK), label)
        check(f"{size} room header shows verified",
              app.query_one("#room-online").render() == "@bob · online · verified",
              app.query_one("#room-online").render())

        # ---- (f) F1 opens help with every key and command; Esc closes
        entry_counts = {k: len(v[0]._entries) for k, v in app.conversations.items()}
        await pilot.press("f1"); await pilot.pause(); await asyncio.sleep(0.1)
        assert isinstance(app.screen, HelpScreen), type(app.screen)
        help_text = "".join(str(w.render()) for w in app.screen.query(Static))
        check(f"{size} help has every binding key",
              all(b.key in help_text for b in app.BINDINGS if b.show), help_text[:80])
        check(f"{size} help has every command",
              all(name in help_text for name, _ in COMMANDS), help_text[:80])
        hbox = app.screen.query_one("#help-box")
        hr = hbox.region
        check(f"{size} help modal inside screen",
              hr.width > 0 and hr.height > 0 and hr.right <= app.size.width and hr.bottom <= app.size.height,
              hr)
        app.save_screenshot(f"screenshot_help_{size[0]}x{size[1]}.svg")
        await pilot.press("escape"); await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} Esc closes help", not isinstance(app.screen, HelpScreen))
        check(f"{size} F1/F2 changed no conversation view",
              {k: len(v[0]._entries) for k, v in app.conversations.items()} == entry_counts)

        # ---- (g) typed slash commands open the modals and write nothing
        counts = {k: len(v[0]._entries) for k, v in app.conversations.items()}
        await _submit(pilot, app, "/help")
        check(f"{size} /help opens the help modal", isinstance(app.screen, HelpScreen),
              type(app.screen).__name__)
        await pilot.press("escape"); await pilot.pause(); await asyncio.sleep(0.1)
        await _submit(pilot, app, "/peers")
        check(f"{size} /peers opens the peers modal", isinstance(app.screen, PeersScreen),
              type(app.screen).__name__)
        await pilot.press("escape"); await pilot.pause(); await asyncio.sleep(0.1)
        await _submit(pilot, app, "/w")
        check(f"{size} /w opens the peers modal", isinstance(app.screen, PeersScreen),
              type(app.screen).__name__)
        await pilot.press("escape"); await pilot.pause(); await asyncio.sleep(0.1)
        check(f"{size} slash commands wrote no conversation line",
              {k: len(v[0]._entries) for k, v in app.conversations.items()} == counts)


async def _glyph_scenario(size: tuple[int, int]) -> None:
    """(g) Status events re-render the DM line with the right glyph (real event bus path)."""
    app, state = _make_app()
    _add_peer(state, FAKE_PEER, "bob")
    mid = "MSG-GLYPH-1"
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await asyncio.sleep(0.1)
        app.open_dm(FAKE_PEER)
        await pilot.pause()
        await asyncio.sleep(0.1)
        view = app.query_one(f"#conv-{FAKE_PEER}", ConversationView)

        def row() -> int:
            return next(i for i, t in enumerate(_line_texts(view)) if "hello bob" in t)

        app.event_bus.publish_nowait(
            AppEvent(EventType.OUTPUT, "hello bob", FAKE_PEER, msg_id=mid, is_self=True))
        await pilot.pause()
        await asyncio.sleep(0.1)
        assert _line_texts(view)[row()].rstrip().split()[-1] == "...", _line_texts(view)[row()]

        for status, glyph in (("sent", "\u2713"), ("delivered", "\u2713\u2713"),
                              ("read", "\u2713\u2713"), ("unconfirmed", "!")):
            app.event_bus.publish_nowait(AppEvent(EventType.DM_STATUS, {
                "conv": FAKE_PEER, "msg_id": mid, "state": status}))
            await pilot.pause()
            await asyncio.sleep(0.1)
            text = _line_texts(view)[row()].rstrip()
            assert text.split()[-1] == glyph, (status, text)
            print(f"  {size} {status}: {text!r}")

        # Read glyph is drawn in the accent colour.
        app.event_bus.publish_nowait(AppEvent(EventType.DM_STATUS, {
            "conv": FAKE_PEER, "msg_id": mid, "state": "read"}))
        await pilot.pause()
        await asyncio.sleep(0.1)
        segs = [s for s in view.lines[row()] if "\u2713" in s.text]
        assert segs, "no tick segment on the read line"
        colour = segs[-1].style.color.get_truecolor()
        assert colour == Color.parse(palette.EMERALD).get_truecolor(), colour

        # One echo line only: re-rendering must not duplicate it.
        assert sum("hello bob" in t for t in _line_texts(view)) == 1


async def _scenario(size: tuple[int, int], label: str) -> None:
    app, state = _make_app()
    _add_peer(state, FAKE_PEER, "bob")
    _add_peer(state, FAKE_PEER2, "carol")

    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await asyncio.sleep(0.1)

        # ---- (h) layout -------------------------------------------------
        print(f"--- {label} ---")
        for sel in ("#app-header", "#conv-tabs", "#conv-general", "#input", "#footer"):
            widget = app.query_one(sel)
            region = widget.region
            print(f"{sel}: {region}")
            assert region.width > 0, f"{sel} width is 0"
            assert region.height > 0, f"{sel} height is 0"
            assert region.x >= 0, f"{sel} x < 0"
            assert region.y >= 0, f"{sel} y < 0"
            assert region.right <= app.size.width, f"{sel} right > screen width"
            assert region.bottom <= app.size.height, f"{sel} bottom > screen height"
        assert app.query_one("#input").region.width >= 20, "#input narrower than 20"
        assert app.query_one("#app-header").region.height <= 5, "header taller than 5 rows"
        print("Tabs:", app.query_one("#conv-tabs").region)
        print("#input:", app.query_one("#input").region)

        # ---- (a) start: one tab, General active -------------------------
        assert app._open_keys() == ["general"], app._open_keys()
        assert app._current_conv == "general"
        assert app.query_one("#conv-tabs", Tabs).active == "tab-general"

        # ---- (b) open a DM tab, send privately --------------------------
        app.open_dm(FAKE_PEER)
        await pilot.pause()
        await asyncio.sleep(0.1)
        assert app._open_keys() == ["general", FAKE_PEER], app._open_keys()
        assert app._current_conv == FAKE_PEER
        assert app.query_one(f"#tab-{FAKE_PEER}", Tab).label_text == "@bob", app.query_one(f"#tab-{FAKE_PEER}", Tab).label_text
        assert app.query_one("#room-online").render() == "@bob · online · unverified"

        # Clicking a tab activates it (the Tabs.TabActivated path).
        await pilot.click("#tab-general")
        await pilot.pause()
        await asyncio.sleep(0.1)
        assert app._current_conv == "general"
        await pilot.click(f"#tab-{FAKE_PEER}")
        await pilot.pause()
        await asyncio.sleep(0.1)
        assert app._current_conv == FAKE_PEER
        app.ble_service.read_receipts_for_peer.assert_awaited_with(FAKE_PEER)

        await _submit(pilot, app, "hello")
        app.ble_service.send_private_message.assert_awaited_once_with(FAKE_PEER, "hello")
        app.ble_service.send_public_message.assert_not_called()

        # ---- (c) alt+left back to General, send publicly ----------------
        await pilot.press("alt+left")
        await pilot.pause()
        await asyncio.sleep(0.1)
        assert app._current_conv == "general"
        assert app.query_one("#room-online").render() == "# General · 3 online"

        await _submit(pilot, app, "hi")
        app.ble_service.send_public_message.assert_awaited_once_with("hi")
        assert app.ble_service.send_private_message.await_count == 1

        # ---- (d) per-conversation routing + unread ----------------------
        app.ble_service._chat("bob", "yo", conv="general")
        app.ble_service._chat("bob", "psst", conv=FAKE_PEER)
        await pilot.pause()
        await asyncio.sleep(0.2)

        general_view = app.query_one("#conv-general")
        assert "yo" in _view_text(general_view), _view_text(general_view)
        assert "psst" not in _view_text(general_view)
        # General is active, so the DM tab carries the unread marker.
        assert "(1)" in app.query_one(f"#tab-{FAKE_PEER}", Tab).label_text

        await pilot.press("alt+right")
        await pilot.pause()
        await asyncio.sleep(0.2)
        assert app._current_conv == FAKE_PEER
        dm_view = app.query_one(f"#conv-{FAKE_PEER}")
        assert "psst" in _view_text(dm_view), _view_text(dm_view)
        assert "yo" not in _view_text(dm_view)
        assert "(1)" not in app.query_one(f"#tab-{FAKE_PEER}", Tab).label_text

        # ---- (e) incoming DM for a peer with no tab ---------------------
        await pilot.press("alt+left")
        await pilot.pause()
        await asyncio.sleep(0.1)
        assert app._current_conv == "general"
        app.ble_service._chat("carol", "hey", conv=FAKE_PEER2)
        await pilot.pause()
        await asyncio.sleep(0.2)
        assert FAKE_PEER2 in app._open_keys(), app._open_keys()
        assert app._current_conv == "general", app._current_conv
        assert "(1)" in app.query_one(f"#tab-{FAKE_PEER2}", Tab).label_text
        # The line is queued until the tab is shown.
        app.open_dm(FAKE_PEER2)
        await pilot.pause()
        await asyncio.sleep(0.2)
        assert "hey" in _view_text(app.query_one(f"#conv-{FAKE_PEER2}"))

        # ---- (f) /send is blocked in a DM tab ---------------------------
        app.open_dm(FAKE_PEER)
        await pilot.pause()
        await asyncio.sleep(0.1)
        await _submit(pilot, app, "/send /etc/hostname")
        app.ble_service.send_file.assert_not_called()
        assert "File DMs are not supported yet" in _view_text(
            app.query_one(f"#conv-{FAKE_PEER}")
        )

        # ---- (g) ctrl+w closes the DM tab, history survives -------------
        await pilot.press("ctrl+w")
        await pilot.pause()
        await asyncio.sleep(0.2)
        assert FAKE_PEER not in app._open_keys(), app._open_keys()
        assert app._current_conv == "general"
        assert "psst" in _view_text(app.query_one(f"#conv-{FAKE_PEER}"))
        app.open_dm(FAKE_PEER)
        await pilot.pause()
        await asyncio.sleep(0.1)
        assert FAKE_PEER in app._open_keys(), app._open_keys()
        assert "psst" in _view_text(app.query_one(f"#conv-{FAKE_PEER}"))

        # ---- (h) F4 settings, F1/F2/F3 ----------------------------------
        await pilot.press("f4")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen), type(app.screen)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, SettingsScreen), "settings did not close"
        for key in ("f1", "f2", "f3"):
            await pilot.press(key)
            await pilot.pause()
            await asyncio.sleep(0.1)
        await app.workers.wait_for_complete()

        screenshot = Path(__file__).parent.parent / f"screenshot_{size[0]}x{size[1]}.svg"
        app.save_screenshot(str(screenshot))
        print(f"saved {screenshot}")


async def _theme_scenario(size: tuple[int, int]) -> None:
    """(h) "bitchat" is the default theme; switching themes restyles the UI."""
    app, state = _make_app()
    _add_peer(state, FAKE_PEER, "bob")
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await asyncio.sleep(0.3)
        check(f"{size} default theme is bitchat", app.theme == "bitchat", app.theme)

        def snap() -> dict:
            hdr = app.query_one("#app-header")
            tabs = app.query_one("#conv-tabs")
            return {
                "header": str(hdr.styles.border),
                "tab": str(tabs.active_tab.styles.color),
                "input": str(app.query_one("#input").styles.color),
                "footer": str(app.query_one("#footer").styles.background),
            }

        def segment_colour(view, needle: str):
            """Truecolour of the first segment containing `needle`, else None."""
            for ln in view.lines:
                for seg in ln:
                    if needle in seg.text and seg.style is not None and seg.style.color is not None:
                        return seg.style.color.get_truecolor()
            return None

        # --- General chat line, checked while the General tab is active
        app.event_bus.publish_nowait(AppEvent(
            EventType.OUTPUT, theme_mod.chat("bob", "theme probe", is_self=False), GENERAL))
        await pilot.pause()
        await asyncio.sleep(0.2)

        general = app.conversations[GENERAL][0]
        base = snap()
        base_line = segment_colour(general, "bob")
        check(f"{size} bitchat chat line uses the palette accent",
              base_line == Color.parse(palette.PINK).get_truecolor(), base_line)
        app.save_screenshot(f"screenshot_theme_bitchat_{size[0]}x{size[1]}.svg")

        for name in ("nord", "textual-light"):
            app.theme = name
            await pilot.pause()
            await asyncio.sleep(0.4)
            s = snap()
            check(f"{size} {name} restyles the header", s["header"] != base["header"], s)
            check(f"{size} {name} restyles the active tab", s["tab"] != base["tab"], s)
            check(f"{size} {name} restyles the input", s["input"] != base["input"], s)
            check(f"{size} {name} restyles the footer", s["footer"] != base["footer"], s)
            check(f"{size} {name} restyles the chat line",
                  segment_colour(general, "bob") != base_line, segment_colour(general, "bob"))
            if name == "nord":
                app.save_screenshot(f"screenshot_theme_nord_{size[0]}x{size[1]}.svg")

        app.theme = "bitchat"
        await pilot.pause()
        await asyncio.sleep(0.4)
        back = snap()
        check(f"{size} bitchat restores the header", back["header"] == base["header"], back)
        check(f"{size} bitchat restores the active tab", back["tab"] == base["tab"], back)
        check(f"{size} bitchat restores the input", back["input"] == base["input"], back)
        check(f"{size} bitchat restores the footer", back["footer"] == base["footer"], back)
        check(f"{size} bitchat restores the chat line",
              segment_colour(general, "bob") == base_line, segment_colour(general, "bob"))

        # --- DM tick glyph, checked while the DM tab is active
        app.open_dm(FAKE_PEER)
        mid = "MSG-THEME-1"
        app.event_bus.publish_nowait(AppEvent(
            EventType.OUTPUT, "theme dm", FAKE_PEER, msg_id=mid, is_self=True))
        app.event_bus.publish_nowait(AppEvent(
            EventType.DM_STATUS, {"conv": FAKE_PEER, "msg_id": mid, "state": "read"}))
        await pilot.pause()
        await asyncio.sleep(0.2)

        dm = app.conversations[FAKE_PEER][0]
        base_tick = segment_colour(dm, "\u2713")
        check(f"{size} bitchat tick uses the palette primary",
              base_tick == Color.parse(palette.EMERALD).get_truecolor(), base_tick)

        for name in ("nord", "textual-light"):
            app.theme = name
            await pilot.pause()
            await asyncio.sleep(0.4)
            check(f"{size} {name} restyles the tick glyph",
                  segment_colour(dm, "\u2713") != base_tick, segment_colour(dm, "\u2713"))

        app.theme = "bitchat"
        await pilot.pause()
        await asyncio.sleep(0.4)
        check(f"{size} bitchat restores the tick glyph",
              segment_colour(dm, "\u2713") == base_tick, segment_colour(dm, "\u2713"))


async def test_tabs_and_routing() -> None:
    await _scenario((80, 24), "80x24")
    await _scenario((120, 40), "120x40")
    await _glyph_scenario((80, 24))
    await _modal_scenario((80, 24))
    await _modal_scenario((120, 40))
    await _theme_scenario((80, 24))
    print("All tests passed!")


if __name__ == "__main__":
    asyncio.run(test_tabs_and_routing())

