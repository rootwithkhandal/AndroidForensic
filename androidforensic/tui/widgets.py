from textual.app import ComposeResult
from textual.widgets import Static, RichLog, ProgressBar
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive
from rich.text import Text

from ..adb_conn import ADBConn


class ConsoleLog(RichLog):
    """Bottom-docked console log output widget."""
    
    def on_mount(self) -> None:
        self.write("[bold cyan]AndroidForensic Everywhere TUI Console Ready.[/bold cyan]")
        self.write("[dim]System messages and execution logs will appear below.[/dim]")
    
    def log_message(self, message: str, style: str = "white") -> None:
        self.write(Text(message, style=style))


class DeviceStatusWidget(Static):
    """Real-time device connection status indicator."""
    
    serial = reactive("Checking...")
    status = reactive("Unknown")
    privilege = reactive("Unknown")
    
    def on_mount(self) -> None:
        self.update_status()
        self.set_interval(5.0, self.update_status)
    
    def update_status(self) -> None:
        try:
            adb = ADBConn()
            ser, stat = adb.device()
            if ser:
                self.serial = ser
                self.status = stat
                try:
                    out = adb.adb_out("id")
                    self.privilege = "ROOT (uid=0)" if "uid=0(root)" in out else "SHELL (non-root)"
                except Exception:
                    self.privilege = "SHELL"
            else:
                self.serial = "No Device Connected"
                self.status = "Disconnected"
                self.privilege = "-"
        except Exception:
            self.serial = "ADB Error"
            self.status = "Error"
            self.privilege = "-"
        
        self.render_content()
    
    def watch_serial(self, new_val: str) -> None:
        self.render_content()
        
    def render_content(self) -> None:
        color = "green" if self.status == "device" else "red" if "No Device" in self.serial else "yellow"
        text = (
            f"[bold cyan]Device Status:[/bold cyan] "
            f"Serial: [bold {color}]{self.serial}[/bold {color}] | "
            f"State: [{color}]{self.status}[/{color}] | "
            f"Privilege: [bold yellow]{self.privilege}[/bold yellow]"
        )
        self.update(text)


class ProgressPanel(Vertical):
    """Progress widget for extraction and password cracking tasks."""
    
    def __init__(self, title: str = "Task Progress", **kwargs):
        super().__init__(**kwargs)
        self.title_text = title
        self.progress_bar = ProgressBar(total=100, show_eta=True, id="task-progress")
        self.status_label = Static("Idle", id="task-status-label")
        
    def compose(self) -> ComposeResult:
        yield Static(f"[bold accent]{self.title_text}[/bold accent]", classes="card-title")
        yield self.status_label
        yield self.progress_bar
        
    def set_status(self, text: str) -> None:
        self.status_label.update(f"[cyan]Current step:[/cyan] {text}")
        
    def set_progress(self, percentage: float) -> None:
        self.progress_bar.progress = percentage
        
    def reset(self) -> None:
        self.progress_bar.progress = 0
        self.status_label.update("Idle")
