"""VaultSync Desktop client entry point."""

import argparse
import sys
from PySide6.QtWidgets import QApplication

from vaultsync_desktop.async_bridge import get_dispatcher
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.storage import AppConfig
from vaultsync_desktop.ui.main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VaultSync — Native Fedora Desktop Client for Self-Hosted E2EE Password Manager",
    )
    parser.add_argument(
        "--server",
        help="Default sync server URL (e.g. http://127.0.0.1:8000 or https://vault.local:8000)",
    )
    args = parser.parse_args(argv)

    app = QApplication(sys.argv)
    app.setApplicationName("VaultSync")
    app.setApplicationDisplayName("VaultSync")
    app.setOrganizationName("VaultSync")

    # Ensure AsyncDispatcher singleton is initialized on Qt GUI thread
    dispatcher = get_dispatcher()

    config = AppConfig()
    if args.server:
        config.server_url = args.server

    session = VaultSession(config=config)
    window = MainWindow(session=session)
    window.show()

    ret = app.exec()
    dispatcher.stop()
    return ret


if __name__ == "__main__":
    sys.exit(main())
