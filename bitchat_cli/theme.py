# theme.py
#
# Centralised terminal styling for the chat UI: a small semantic colour palette
# plus formatters for chat lines, media, system notices, and events. Everything
# degrades to plain text when output isn't a TTY or NO_COLOR is set, so logs and
# redirected output stay clean.

import hashlib
import os
import sys
import time

from . import palette


def _color_enabled() -> bool:
    # https://no-color.org/ — any value (even empty) disables colour.
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("BITCHAT_FORCE_COLOR"):
        return True
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


ENABLED = _color_enabled()


def _fg(n: int) -> str:
    """256-colour foreground SGR parameter."""
    return f"38;5;{n}"


def sgr(text: str, *codes: str) -> str:
    """Wrap text in SGR codes (no-op when colour is disabled)."""
    if not ENABLED or not codes:
        return text
    return "".join(f"\033[{c}m" for c in codes) + text + "\033[0m"


# --- Semantic palette (derived from palette.py) -------------------------- #
BOLD = "1"
DIM = "2"
BRAND = palette.sgr_fg(palette.EMERALD)    # bitchat green — logo, prompt, accents
OWN = palette.sgr_fg(palette.CYAN)         # local user
REMOTE = palette.sgr_fg(palette.PINK)      # remote users
TIME = palette.sgr_fg(palette.MUTED)       # timestamps
SYS = palette.sgr_fg(palette.MUTED)        # neutral system info
OK = BRAND                                 # success / connected
JOIN = BRAND                               # peer came online
LEAVE = palette.sgr_fg(palette.MUTED)      # peer went offline
ERR = palette.sgr_fg(palette.RED)          # errors
WARN = palette.sgr_fg(palette.AMBER)       # warnings
MEDIA = palette.sgr_fg(palette.PINK)       # media labels
PATH = palette.sgr_fg(palette.MUTED)       # file paths
LABEL = palette.sgr_fg(palette.MUTED)      # banner field labels

# (true-colour palette only; no 256-colour helpers remain)

_MEDIA_ICON = {"image": "🖼", "audio": "🎙", "file": "📎"}


# (nick_color removed; remote senders use REMOTE)


def _hm(ts_ms=None) -> str:
    t = time.localtime(ts_ms / 1000) if ts_ms else time.localtime()
    return time.strftime("%H:%M", t)


# --- Line formatters ----------------------------------------------------- #
def chat(sender: str, content: str, ts_ms=None, is_self: bool = False) -> str:
    color = OWN if is_self else REMOTE
    return f"{sgr(_hm(ts_ms).ljust(5), TIME)}  {sgr(sender.ljust(12), BOLD, color)}  {content}"


def media(sender: str, category: str, label: str, path=None,
          ts_ms=None, is_self: bool = False) -> str:
    color = OWN if is_self else REMOTE
    icon = _MEDIA_ICON.get(category, _MEDIA_ICON["file"])
    body = sgr(f"{icon} {label}", MEDIA)
    if path is not None:
        body += " " + sgr(f"→ {path}", PATH)
    return f"{sgr(_hm(ts_ms).ljust(5), TIME)}  {sgr(sender.ljust(12), BOLD, color)}  {body}"


def system(msg: str) -> str:
    return f"{sgr('·', SYS)} {sgr(msg, SYS)}"


def ok(msg: str) -> str:
    return f"{sgr('✓', BOLD, OK)} {sgr(msg, OK)}"


def join(msg: str) -> str:
    return f"{sgr('>', BOLD, JOIN)} {sgr(msg, JOIN)}"


def leave(msg: str) -> str:
    return f"{sgr('←', LEAVE)} {sgr(msg, LEAVE)}"


def warn(msg: str) -> str:
    return f"{sgr('!', BOLD, WARN)} {sgr(msg, WARN)}"


def error(msg: str) -> str:
    return f"{sgr('✗', BOLD, ERR)} {sgr(msg, ERR)}"


def prompt(nick: str) -> str:
    """The input prompt string (wrap in prompt_toolkit ANSI() before use)."""
    return f"{sgr(nick, BOLD, BRAND)}{sgr(' ❯ ', BRAND)}"


# --- Multi-line blocks --------------------------------------------------- #
_LOGO = r"""
██████╗ ██╗████████╗ ██████╗██╗  ██╗ █████╗ ████████╗
██╔══██╗██║╚══██╔══╝██╔════╝██║  ██║██╔══██╗╚══██╔══╝
██████╔╝██║   ██║   ██║     ███████║███████║   ██║
██╔══██╗██║   ██║   ██║     ██╔══██║██╔══██║   ██║
██████╔╝██║   ██║   ╚██████╗██║  ██║██║  ██║   ██║
╚═════╝ ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝"""


def banner(nickname: str, peer_id: str, version: str) -> str:
    """The startup welcome block."""
    logo = sgr(_LOGO, BRAND)
    tag = sgr(f"C L I  ·  v{version}", BOLD, BRAND)
    field = lambda k, v, c: f"{sgr(k, LABEL)} {sgr(v, BOLD, c)}"
    lines = [
        logo,
        f"                  {tag}",
        "",
        "  " + field("you", nickname, OWN) + sgr("   ·   ", LABEL) + field("peer", peer_id, SYS),
        "  " + sgr("Messages are broadcast publicly to bitchat peers in range.", SYS),
        "  " + sgr("Type a message and press Enter, or ", SYS)
        + sgr("/help", BOLD, BRAND) + sgr(" for commands.", SYS),
    ]
    return "\n".join(lines)
