"""Layout and screen interaction tests for BitchatApp."""
import asyncio
import sys
from pathlib import Path

# Add project root to sys.path if running directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from textual.widgets import Input

from bitchat_cli.app import BitchatApp
from bitchat_cli.chat_state import ChatState
from bitchat_cli.screens import SettingsScreen


async def test_layout_and_screens() -> None:
    state = ChatState(nickname="Tester")
    app = BitchatApp(state)

    # Stub BLE service to avoid hardware dependency
    async def stub_run():
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass

    app.ble_service.run = stub_run  # type: ignore

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await asyncio.sleep(0.1)

        print("--- Size 80x24 ---")
        widgets = [
            "#app-header",
            "#wordmark",
            "#link-state",
            "#room-online",
            "#chat",
            "#input",
            "#input-panel",
            "#footer",
        ]
        for w in widgets:
            widget = app.query_one(w)
            region = widget.region
            print(f"{w}: {region}")
            assert region.width > 0, f"{w} width is 0"
            assert region.height > 0, f"{w} height is 0"
            assert region.x >= 0, f"{w} x < 0"
            assert region.y >= 0, f"{w} y < 0"
            assert region.right <= app.size.width, f"{w} right > screen width"
            assert region.bottom <= app.size.height, f"{w} bottom > screen height"

        input_widget = app.query_one("#input")
        assert input_widget.region.width >= 20, f"#input width {input_widget.region.width} < 20"

        header = app.query_one("#app-header")
        assert header.region.height == 3, f"#app-header height {header.region.height} != 3"

        # Test F4
        await pilot.press("f4")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen), f"Screen is {type(app.screen)}"
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, SettingsScreen), "Settings did not close"

        # Test F2, F3, F1
        for key in ["f2", "f3", "f1"]:
            await pilot.press(key)
            await pilot.pause()
            await asyncio.sleep(0.1)

        await app.workers.wait_for_complete()
        app.save_screenshot("screenshot_80x24.svg")

    print("--- 80x24 passed, creating new app for 120x40 ---")

    state2 = ChatState(nickname="Tester2")
    app = BitchatApp(state2)
    app.ble_service.run = stub_run  # type: ignore

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await asyncio.sleep(0.1)

        print("--- Size 120x40 ---")
        for w in widgets:
            widget = app.query_one(w)
            region = widget.region
            print(f"{w}: {region}")
            assert region.width > 0
            assert region.height > 0
            assert region.x >= 0
            assert region.y >= 0
            assert region.right <= app.size.width
            assert region.bottom <= app.size.height

        input_widget = app.query_one("#input")
        assert input_widget.region.width >= 20

        header = app.query_one("#app-header")
        assert header.region.height == 3

        await pilot.press("f4")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, SettingsScreen)

        for key in ["f2", "f3", "f1"]:
            await pilot.press(key)
            await pilot.pause()
            await asyncio.sleep(0.1)

        await app.workers.wait_for_complete()
        app.save_screenshot("screenshot_120x40.svg")

    print("All tests passed!")


if __name__ == "__main__":
    asyncio.run(test_layout_and_screens())
