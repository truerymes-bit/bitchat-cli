# debuglog.py
#
# Verbose debug log with a size cap.  Appends timestamped lines to
# ~/.bitchat/bitchat-debug.log.  When the file exceeds MAX_BYTES it is trimmed
# to the newest KEEP_BYTES (rolling window, dropping the oldest lines).

import os
import threading
import time
from pathlib import Path

LOG_PATH = Path.home() / ".bitchat" / "bitchat-debug.log"
MAX_BYTES = 2 * 1024 * 1024
KEEP_BYTES = 1024 * 1024

_lock = threading.Lock()


def _trim() -> None:
    with open(LOG_PATH, "rb") as f:
        f.seek(-KEEP_BYTES, os.SEEK_END)
        tail = f.read()
    nl = tail.find(b"\n")
    if nl != -1:
        tail = tail[nl + 1:]  # drop the partial first line
    tmp = LOG_PATH.with_suffix(".log.tmp")
    with open(tmp, "wb") as f:
        f.write(tail)
    os.replace(tmp, LOG_PATH)


def dlog(msg: str) -> None:
    """Append one timestamped line; never raises."""
    try:
        with _lock:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n"
            with open(LOG_PATH, "a") as f:
                f.write(line)
            if LOG_PATH.stat().st_size > MAX_BYTES:
                _trim()
    except Exception:
        pass
