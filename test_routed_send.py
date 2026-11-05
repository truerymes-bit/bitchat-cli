"""Offline tests for send_routed_message delivery path.

Runs in the project venv (needs `noise`/`bleak`). Skips cleanly otherwise.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import noise  # noqa: F401
    import bleak  # noqa: F401
except ImportError:
    print("SKIP: noise/bleak not installed")
    sys.exit(0)

from unittest.mock import AsyncMock, MagicMock

from bitchat_cli.ble_service import BLEService
from bitchat_cli.chat_state import ChatState


def _make_service(route_ids, connected_peer=None, connected_addr="addr1"):
    """Build a minimal BLEService with a fake clients/_peer_addr map."""
    state = ChatState(nickname="self", my_peer_id=bytes.fromhex("aaaaaaaaaaaaaaaa"))
    svc = BLEService.__new__(BLEService)
    svc.state = state
    svc._sync_manager = None
    svc._sys = lambda *a, **k: None
    svc._chat = lambda *a, **k: None
    svc._peripheral = MagicMock()
    svc.clients = {}
    svc._peer_addr = {}
    if connected_peer is not None:
        svc.clients[connected_addr] = MagicMock(is_connected=True)
        svc.clients[connected_addr].write_gatt_char = AsyncMock()
        svc._peer_addr[connected_peer] = connected_addr
    # Monkeypatch compute_route to return the requested value.
    state.compute_route = lambda s, r: route_ids
    return svc


async def case_unicast_first_hop():
    svc = _make_service(["bbbbbbbbbbbbbbbb"], connected_peer="bbbbbbbbbbbbbbbb")
    await svc.send_routed_message("cccccccccccccccc", "hi")
    assert svc.clients["addr1"].write_gatt_char.called, "expected unicast write"
    assert not svc._peripheral.notify_all.called, "notify_all must not fire on unicast path"


async def case_unicast_direct_recipient():
    svc = _make_service([], connected_peer="cccccccccccccccc")
    await svc.send_routed_message("cccccccccccccccc", "hi")
    assert svc.clients["addr1"].write_gatt_char.called, "expected unicast write to recipient"


async def case_flood_no_connection():
    svc = _make_service(["bbbbbbbbbbbbbbbb"], connected_peer=None)
    broadcast = AsyncMock()
    svc._broadcast = broadcast
    await svc.send_routed_message("cccccccccccccccc", "hi")
    assert broadcast.called, "expected broadcast fallback"


async def case_flood_on_write_failure():
    svc = _make_service(["bbbbbbbbbbbbbbbb"], connected_peer="bbbbbbbbbbbbbbbb")
    svc.clients["addr1"].write_gatt_char = AsyncMock(side_effect=Exception("boom"))
    broadcast = AsyncMock()
    svc._broadcast = broadcast
    await svc.send_routed_message("cccccccccccccccc", "hi")
    assert broadcast.called, "expected broadcast fallback after write failure"


def main():
    for name, coro in [
        ("unicast_first_hop", case_unicast_first_hop()),
        ("unicast_direct_recipient", case_unicast_direct_recipient()),
        ("flood_no_connection", case_flood_no_connection()),
        ("flood_on_write_failure", case_flood_on_write_failure()),
    ]:
        try:
            asyncio.run(coro)
            print(f"  ok  - {name}")
        except Exception as e:
            print(f"  FAIL - {name}: {e}")
            sys.exit(1)
    print("\nAll routed-send checks passed.")


if __name__ == "__main__":
    main()
