# main.py
import argparse
import logging
from pathlib import Path

from .chat_state import ChatState


def main():
    parser = argparse.ArgumentParser(description="Bitchat TUI")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    log_dir = Path.home() / ".bitchat"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        filename=str(log_dir / "bitchat.log"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    state = ChatState(nickname="")

    from .app import BitchatApp
    app = BitchatApp(state)
    app.run()


if __name__ == "__main__":
    main()
