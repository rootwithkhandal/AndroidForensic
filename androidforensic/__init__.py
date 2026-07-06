__version__ = "4.0.0"
__app_name__ = "AndroidForensic Everywhere"
__package_name__ = "androidforensic"
__website__ = "https://github.com/AnonCatalyst/AndroidForensic"
__license__ = "MIT"
__all__ = ["cli", "tui", "web"]

import logging

logger = logging.getLogger(__name__)


def cli_main():
    """Entry point for the CLI (Click-based)."""
    from .cli.main import cli
    cli()


def gui_main():
    """Entry point for the web-based GUI (Flask)."""
    from .web.app import create_app
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)


def tui_main():
    """Entry point for the TUI (Textual-based)."""
    from .tui.app import AndroidForensicTUI
    app = AndroidForensicTUI()
    app.run()


def run():
    """Legacy entry point — dispatches to CLI by default."""
    cli_main()
