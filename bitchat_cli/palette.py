"""Single source of truth for the bitchat TUI colour palette.

Values come from INTERFACE_DESIGN.md. Everything else (theme.py ANSI codes,
widgets.py Rich styles, app.tcss via CSS variables) derives from here.
"""
from __future__ import annotations

# Surfaces
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


def sgr_fg(hex_colour: str) -> str:
    """'#RRGGBB' -> true-colour foreground SGR parameter string."""
    h = hex_colour.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"38;2;{r};{g};{b}"


def css_variables() -> dict:
    """Variables exposed to app.tcss as $bc-<name>."""
    return {
        "bc-bg": BG, "bc-panel": PANEL, "bc-panel-alt": PANEL_ALT, "bc-bar": BAR,
        "bc-emerald": EMERALD, "bc-green": GREEN, "bc-cyan": CYAN,
        "bc-pink": PINK, "bc-amber": AMBER, "bc-red": RED,
        "bc-text": TEXT, "bc-muted": MUTED,
    }
