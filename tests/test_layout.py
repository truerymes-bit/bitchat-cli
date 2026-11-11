"""Layout, tab and routing tests for BitchatApp (tabbed conversations).

Run with:  /usr/bin/python3 tests/test_layout.py
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from textual.widgets import Input, Tab, Tabs

from bitchat_cli.app import BitchatApp
from bitchat_cli.chat_state import ChatState
from bitchat_cli.screens import SettingsScreen

FAKE_PEER = "a" * 16
FAKE_PEER2 = "b" * 16


async def _stub_run():
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass


def _make_app(nickname: str = "Tester"):
    state = ChatState(nickname=nickname)
    app = BitchatApp(state)
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
        assert app.query_one(f"#tab-{FAKE_PEER}", Tab).label_text == "@bob"
        assert app.query_one("#room-online").render() == "@bob · online"

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


async def test_tabs_and_routing() -> None:
    await _scenario((80, 24), "80x24")
    await _scenario((120, 40), "120x40")
    print("All tests passed!")


if __name__ == "__main__":
    asyncio.run(test_tabs_and_routing())
