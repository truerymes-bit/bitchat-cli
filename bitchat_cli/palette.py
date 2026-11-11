"""Single source of truth for the bitchat TUI colour palette.

The constants below define the default "bitchat" look (INTERFACE_DESIGN.md).
At runtime the active colours are re-derived from the Textual theme's
variables (see `set_theme_colors`), so Ctrl+P > Change theme restyles the whole
UI. `css_variables()` exposes the active colours to app.tcss as `$bc-*`.
"""
from __future__ import annotations

# Default surfaces/accents (the "bitchat" look).
BG = "#101315"          # screen background
PANEL = "#171A1E"       # conversation panel / header
PANEL_ALT = "#1C2228"   # input, status boxes
BAR = "#22272E"         # room header bar

# Accents
EMERALD = "#00D99A"     # primary accent, borders
GREEN = "#00B981"       # secondary green
CYAN = "#35D5E8"        # local user / info
PINK = "#FF6FA5"        # remote users
AMBER = "#FFB52E"       # warnings
RED = "#FF5D65"         # errors / offline

# Text
TEXT = "#E6E9ED"        # primary
MUTED = "#929BA5"       # secondary

_DEFAULTS = {
    "bg": BG, "panel": PANEL, "panel_alt": PANEL_ALT, "bar": BAR,
    "emerald": EMERALD, "green": GREEN, "cyan": CYAN, "pink": PINK,
    "amber": AMBER, "red": RED, "text": TEXT, "muted": MUTED,
}

# The colours currently in force. `set_theme_colors` rewrites this from the
# active Textual theme; everything else reads it through colors().
_ACTIVE = dict(_DEFAULTS)


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    h = hex_colour.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _blend(fg: str, bg: str, t: float) -> str:
    f, b = _rgb(fg), _rgb(bg)
    return "#%02X%02X%02X" % tuple(round(f[i] + (b[i] - f[i]) * t) for i in range(3))


def _is_hex(value) -> bool:
    return isinstance(value, str) and value.startswith("#") and len(value) >= 7


def set_theme_colors(variables: dict | None) -> None:
    """Re-derive the active colours from a Textual theme's CSS variables.

    `variables` is the dict `Theme.to_color_system().generate()` returns (plus
    any `Theme.variables`). Missing or non-colour values fall back to the
    defaults above, so a partial theme still renders.
    """
    v = variables or {}

    def pick(name, fallback):
        value = v.get(name)
        return value if value else fallback

    foreground = pick("foreground", TEXT)
    background = pick("background", BG)
    muted = pick("text-muted", "")
    if not _is_hex(muted):
        # Textual emits "auto 60%" for text-muted, which is not a colour Rich
        # can use; blend the foreground towards the background instead.
        muted = _blend(foreground, background, 0.6)

    global _ACTIVE
    _ACTIVE = {
        "bg": background,
        "panel": pick("panel", PANEL),
        "panel_alt": pick("panel-lighten-1", pick("surface", PANEL_ALT)),
        "bar": pick("panel-lighten-2", pick("surface", BAR)),
        "emerald": pick("primary", EMERALD),
        "green": pick("success", GREEN),
        "cyan": pick("secondary", CYAN),
        "pink": pick("accent", PINK),
        "amber": pick("warning", AMBER),
        "red": pick("error", RED),
        "text": foreground,
        "muted": muted,
    }


def colors() -> dict:
    """The active colours, keyed by lowercase name."""
    return dict(_ACTIVE)


def css_variables() -> dict:
    """Variables exposed to app.tcss as `$bc-<name>`, from the active theme."""
    c = _ACTIVE
    return {
        "bc-bg": c["bg"], "bc-panel": c["panel"], "bc-panel-alt": c["panel_alt"],
        "bc-bar": c["bar"], "bc-emerald": c["emerald"], "bc-green": c["green"],
        "bc-cyan": c["cyan"], "bc-pink": c["pink"], "bc-amber": c["amber"],
        "bc-red": c["red"], "bc-text": c["text"], "bc-muted": c["muted"],
    }


def recolor_map() -> dict:
    """Default-palette RGB -> active hex, for re-colouring stored chat lines.

    Chat lines are stored as ANSI strings produced from the default palette, so
    switching theme re-colours them by mapping each default colour to its
    counterpart in the active theme.
    """
    c = _ACTIVE
    return {
        _rgb(EMERALD): c["emerald"],
        _rgb(GREEN): c["green"],
        _rgb(CYAN): c["cyan"],
        _rgb(PINK): c["pink"],
        _rgb(AMBER): c["amber"],
        _rgb(RED): c["red"],
        _rgb(TEXT): c["text"],
        _rgb(MUTED): c["muted"],
    }


def sgr_fg(hex_colour: str) -> str:
    """'#RRGGBB' -> true-colour foreground SGR parameter string."""
    h = hex_colour.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"38;2;{r};{g};{b}"
