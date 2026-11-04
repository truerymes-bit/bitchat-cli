# cli.py
import asyncio
import os

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.patch_stdout import patch_stdout

from . import __version__, theme
from .ble_service import BLEService
from .chat_state import ChatState


class CLI:
    """Command-line interface and input loop."""

    def __init__(self, state: ChatState):
        self.state = state
        self.ble_service = BLEService(state, self.redraw_prompt)
        self.session = PromptSession(
            completer=WordCompleter(
                ["/w", "/peers", "/dm", "/route", "/verify", "/unverify", "/name", "/send", "/file", "/clear", "/sync", "/topology", "/help"], ignore_case=True
            )
        )

    def redraw_prompt(self):
        if self.session.app:
            self.session.app.invalidate()

    def get_prompt_message(self):
        # ANSI() lets prompt_toolkit render the coloured prompt correctly.
        return ANSI(theme.prompt(self.state.nickname))

    def _out(self, line: str):
        # ANSI(...) so prompt_toolkit renders the colour codes (a plain print()
        # under patch_stdout() would show the escape sequences literally).
        print_formatted_text(ANSI(line))
        self.redraw_prompt()

    async def handle_command(self, text: str):
        parts = text.split(" ")
        cmd = parts[0].lower()

        if cmd == "/w":
            if not self.state.peer_nicknames:
                self._out(theme.system("No peers yet — still scanning / waiting for announces…"))
            else:
                n = len(self.state.peer_nicknames)
                self._out(theme.system(f"Known peers ({n}):"))
                for peer_id, nick in self.state.peer_nicknames.items():
                    name = theme.sgr(nick, theme.BOLD, theme.nick_color(nick))
                    self._out(f"  {name} {theme.sgr(peer_id, theme.PATH)}")
        elif cmd == "/peers":
            if not getattr(self.state, 'peer_info', None):
                self._out(theme.system("No verified peers yet — waiting for announces…"))
            else:
                import hashlib
                n = len(self.state.peer_info)
                self._out(theme.system(f"Verified peers ({n}):"))
                for peer_id, info in self.state.peer_info.items():
                    noise_pub = info.get("noise_public_key", b"")
                    signing_pub = info.get("signing_public_key", b"")
                    fingerprint = hashlib.sha256(noise_pub).hexdigest()
                    self._out(f"  {theme.sgr(info.get('nickname','?'), theme.BOLD)} "
                              f"{theme.sgr(peer_id, theme.PATH)}")
                    self._out(f"    fingerprint: {fingerprint}")
                    self._out(f"    signing:     {signing_pub.hex()}")
                    # Show verification status
                    verified = self.state.is_verified(peer_id)
                    v_status = "✓ verified" if verified else "⚠ unverified"
                    self._out(f"    verify:      {v_status}")
                    # Show Noise session status
                    sess = self.ble_service._noise_sessions.get(peer_id)
                    if sess is not None:
                        status = "✓ encrypted" if sess.is_finished else "…handshake"
                        self._out(f"    noise:       {status}")
        elif cmd == "/dm":
            if len(parts) < 3:
                self._out(theme.warn("Usage: /dm <peer_id_prefix> <message>"))
            else:
                peer_prefix = parts[1]
                msg = " ".join(parts[2:])
                # Find peer by prefix
                target = None
                for pid in self.state.peer_info:
                    if pid.startswith(peer_prefix):
                        target = pid
                        break
                if target is None:
                    self._out(theme.warn(f"No peer matching '{peer_prefix}'"))
                else:
                    await self.ble_service.send_private_message(target, msg)
        elif cmd == "/route":
            if len(parts) < 3:
                self._out(theme.warn("Usage: /route <peer_id_prefix> <message>"))
            else:
                peer_prefix = parts[1]
                msg = " ".join(parts[2:])
                target = None
                for pid in self.state.peer_info:
                    if pid.startswith(peer_prefix):
                        target = pid
                        break
                if target is None:
                    self._out(theme.warn(f"No peer matching '{peer_prefix}'"))
                else:
                    await self.ble_service.send_routed_message(target, msg)
        elif cmd == "/verify":
            if len(parts) < 2:
                self._out(theme.warn("Usage: /verify <peer_id_prefix>"))
            else:
                peer_prefix = parts[1]
                target = None
                for pid in self.state.peer_info:
                    if pid.startswith(peer_prefix):
                        target = pid
                        break
                if target is None:
                    self._out(theme.warn(f"No peer matching '{peer_prefix}'"))
                else:
                    import hashlib
                    info = self.state.peer_info[target]
                    noise_pub = info.get("noise_public_key", b"")
                    fingerprint = hashlib.sha256(noise_pub).hexdigest()
                    if self.state.verify_peer(target):
                        self._out(theme.system(f"Verified {info.get('nickname','?')} ({target[:8]})"))
                        self._out(theme.system(f"  fingerprint: {fingerprint}"))
                    else:
                        self._out(theme.warn(f"Could not verify {target[:8]}"))
        elif cmd == "/unverify":
            if len(parts) < 2:
                self._out(theme.warn("Usage: /unverify <peer_id_prefix>"))
            else:
                peer_prefix = parts[1]
                target = None
                for pid in self.state.peer_info:
                    if pid.startswith(peer_prefix):
                        target = pid
                        break
                if target is None:
                    self._out(theme.warn(f"No peer matching '{peer_prefix}'"))
                else:
                    if self.state.unverify_peer(target):
                        self._out(theme.system(f"Unverified {self.state.nickname_for(target)} ({target[:8]})"))
                    else:
                        self._out(theme.warn(f"{target[:8]} was not verified"))
        elif cmd == "/name":
            new_nick = text[len("/name"):].strip()
            if not new_nick:
                self._out(theme.warn("Usage: /name <new nickname>"))
            else:
                old = self.state.nickname
                self.state.nickname = new_nick
                self.state.save_nickname()
                await self.ble_service.send_announce()
                self._out(theme.system(f"Nickname changed from '{old}' to '{new_nick}'."))
        elif cmd in ("/send", "/file"):
            path = text[len(cmd):].strip().strip('"').strip("'")
            if not path:
                self._out(theme.warn(f"Usage: {cmd} <path-to-file>"))
            else:
                await self.ble_service.send_file(path)
        elif cmd == "/sync":
            if self.ble_service._sync_manager is not None:
                await self.ble_service._sync_manager.send_periodic_sync()
                self._out(theme.system("Gossip sync requested."))
            else:
                self._out(theme.warn("Sync manager not running."))
        elif cmd == "/topology":
            topo = self.state.topology
            if not topo:
                self._out(theme.system("No topology data yet — waiting for announces with neighbor gossip."))
            else:
                self._out(theme.system("Mesh topology:"))
                for peer_id, neighbors in topo.items():
                    nick = self.state.nickname_for(peer_id)
                    nlist = ", ".join(n[:8] for n in neighbors) if neighbors else "(none)"
                    self._out(f"  {theme.sgr(nick, theme.BOLD)} ({peer_id[:8]}) -> {nlist}")
                # Show confirmed/unconfirmed edges
                conf = self.state.confirmed_edges()
                unconf = self.state.unconfirmed_edges()
                if conf:
                    self._out(theme.system(f"Confirmed edges ({len(conf)}):"))
                    for a, b in conf:
                        self._out(f"  {a[:8]} <-> {b[:8]}")
                if unconf:
                    self._out(theme.system(f"Unconfirmed edges ({len(unconf)}):"))
                    for a, b in unconf:
                        self._out(f"  {a[:8]} -> {b[:8]} (one-way)")
        elif cmd == "/clear":
            print("\033c", end="")
        elif cmd == "/help":
            self._out(theme.system("Commands:"))
            for name, desc in (
                ("/w", "List known peers."),
                ("/peers", "List verified peers with keys."),
                ("/dm <id> <msg>", "Send encrypted private message."),
                ("/route <id> <msg>", "Send message via source-routed path."),
                ("/verify <id>", "Mark a peer as verified (after comparing fingerprints)."),
                ("/unverify <id>", "Remove verification from a peer."),
                ("/name <nick>", "Change your nickname and re-announce."),
                ("/send <path>", "Send an image, voice note, or file to peers."),
                ("/sync", "Trigger a gossip sync with neighbors."),
                ("/topology", "Show mesh topology graph."),
                ("/clear", "Clear the screen."),
                ("/help", "Show this help message."),
            ):
                cmd_col = theme.sgr(name.ljust(14), theme.BOLD, theme.BRAND)
                self._out(f"  {cmd_col} {theme.sgr(desc, theme.SYS)}")
        else:
            candidate = os.path.expanduser(text.strip())
            if os.path.isfile(candidate):
                # A bare file path starts with '/', so it looks like a command.
                self._out(theme.warn(f"To send a file, use:  /send {text.strip()}"))
            else:
                self._out(theme.warn(f"Unknown command: {cmd}. Type /help for commands."))

    async def run(self):
        print_formatted_text(ANSI(theme.banner(
            self.state.nickname, self.state.my_peer_id_hex, __version__)))

        ble_task = None
        try:
            with patch_stdout():
                ble_task = asyncio.create_task(self.ble_service.run())
                while True:
                    self.session.message = self.get_prompt_message
                    text = await self.session.prompt_async()
                    if not text.strip():
                        continue
                    if text.startswith("/"):
                        await self.handle_command(text)
                    else:
                        # send_public_message renders the local echo via the theme.
                        await self.ble_service.send_public_message(text)
        except (EOFError, KeyboardInterrupt):
            print("\n" + theme.system("Shutting down…"))
        finally:
            if ble_task:
                ble_task.cancel()
            await self.ble_service.stop()
            print(theme.system("Shutdown complete."))
