import os
import asyncio
from typing import Optional
from textual.app import App, ComposeResult
from textual.containers import Grid, Vertical, Horizontal, ScrollableContainer
from textual.widgets import Header, Footer, Static, ListView, ListItem, Label, Button, Input, Select, Checkbox, TabbedContent, TabPane, DataTable
from textual.screen import Screen
from textual.worker import Worker

from .. import __version__, __app_name__
from ..config import Config
from ..driller import ChainExecution
from ..cracking import crack_pattern, PasswordCrack
from ..utils import DrillerTools
from ..decoders import AndroidDecoder
from .widgets import ConsoleLog, DeviceStatusWidget, ProgressPanel


class DashboardScreen(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("[bold accent]Welcome to AndroidForensic Everywhere Dashboard[/bold accent]", classes="card-title")
        yield DeviceStatusWidget(classes="panel-card")
        
        with Vertical(classes="panel-card"):
            yield Static("[bold]System Information & Quick Actions[/bold]", classes="card-title")
            yield Static(f"Version: {__version__}\nToolkit for responsive, multi-interface forensic acquisition and decoding.")
            with Horizontal():
                yield Button("USB Extraction", variant="primary", id="quick-usb", classes="action-btn")
                yield Button("Lockscreen Cracking", variant="warning", id="quick-crack", classes="action-btn")


class ExtractionScreen(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("[bold accent]Data Acquisition & Extraction[/bold accent]", classes="card-title")
        with TabbedContent(initial="tab-usb"):
            with TabPane("USB Device", id="tab-usb"):
                with Vertical(classes="panel-card"):
                    yield Static("Acquire data directly from connected Android device over USB/ADB.")
                    yield Horizontal(
                        Label("Output Dir:", classes="form-label"),
                        Input(value=os.path.expanduser("~"), id="usb-out-dir", classes="form-input"),
                        classes="form-row"
                    )
                    yield Checkbox("Include Shared Storage (SD Card / Media)", id="usb-shared", value=False)
                    yield Button("Start USB Extraction", variant="success", id="btn-start-usb", classes="action-btn")
            
            with TabPane("Folder Parse", id="tab-folder"):
                with Vertical(classes="panel-card"):
                    yield Static("Parse and decode an existing data directory.")
                    yield Horizontal(
                        Label("Source Dir:", classes="form-label"),
                        Input(placeholder="/path/to/extracted/data", id="folder-src-dir", classes="form-input"),
                        classes="form-row"
                    )
                    yield Horizontal(
                        Label("Output Dir:", classes="form-label"),
                        Input(value=os.path.expanduser("~"), id="folder-out-dir", classes="form-input"),
                        classes="form-row"
                    )
                    yield Button("Start Folder Parsing", variant="success", id="btn-start-folder", classes="action-btn")
                    
            with TabPane("Backup (.ab)", id="tab-ab"):
                with Vertical(classes="panel-card"):
                    yield Static("Convert and parse an Android Backup (.ab) file.")
                    yield Horizontal(
                        Label("AB File:", classes="form-label"),
                        Input(placeholder="/path/to/backup.ab", id="ab-src-file", classes="form-input"),
                        classes="form-row"
                    )
                    yield Horizontal(
                        Label("Output Dir:", classes="form-label"),
                        Input(value=os.path.expanduser("~"), id="ab-out-dir", classes="form-input"),
                        classes="form-row"
                    )
                    yield Button("Start AB Parsing", variant="success", id="btn-start-ab", classes="action-btn")


class DecodersScreen(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("[bold accent]Registered Forensic Decoders[/bold accent]", classes="card-title")
        yield Static("List of all active artifact decoders in the registry:")
        dt = DataTable(id="decoders-table")
        dt.add_columns("Decoder Class", "Target Artifact", "Package Namespace")
        for sub in AndroidDecoder.get_subclasses():
            if not sub.exclude_from_registry:
                dt.add_row(sub.__name__, str(sub.RETARGET or sub.TARGET), str(sub.PACKAGE or "-"))
        yield dt


class LockscreenScreen(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("[bold accent]Lockscreen Cracking Tools[/bold accent]", classes="card-title")
        with TabbedContent():
            with TabPane("Gesture Pattern", id="tab-pattern"):
                with Vertical(classes="panel-card"):
                    yield Static("Crack gesture pattern from SHA1 hex hash or gesture.key file.")
                    yield Horizontal(
                        Label("Pattern Hash:", classes="form-label"),
                        Input(placeholder="e.g. c8c0b24a15dc8bbf...", id="pattern-hash-input", classes="form-input"),
                        classes="form-row"
                    )
                    yield Button("Crack Pattern", variant="warning", id="btn-crack-pattern", classes="action-btn")
            
            with TabPane("PIN / Password", id="tab-pin"):
                with Vertical(classes="panel-card"):
                    yield Static("Crack numeric PIN or password using hash and integer salt.")
                    yield Horizontal(
                        Label("Hash (Hex):", classes="form-label"),
                        Input(placeholder="SHA1/MD5 hash hex string", id="pin-hash-input", classes="form-input"),
                        classes="form-row"
                    )
                    yield Horizontal(
                        Label("Salt (Int):", classes="form-label"),
                        Input(placeholder="Integer salt value", id="pin-salt-input", classes="form-input"),
                        classes="form-row"
                    )
                    yield Horizontal(
                        Label("Max PIN Len:", classes="form-label"),
                        Input(value="8", id="pin-len-input", classes="form-input"),
                        classes="form-row"
                    )
                    yield Checkbox("Use Samsung Algorithm (PBKDF/SHA1 loop)", id="pin-samsung-check", value=False)
                    yield Button("Start PIN Crack", variant="warning", id="btn-crack-pin", classes="action-btn")


class ToolsScreen(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("[bold accent]Auxiliary Forensic Utilities[/bold accent]", classes="card-title")
        with Vertical(classes="panel-card"):
            yield Static("[bold]AB to TAR Converter[/bold]", classes="card-title")
            yield Horizontal(
                Label("AB File:", classes="form-label"),
                Input(placeholder="/path/to/backup.ab", id="tool-ab-input", classes="form-input"),
                classes="form-row"
            )
            yield Button("Convert to TAR", variant="primary", id="btn-tool-ab2tar", classes="action-btn")
            
        with Vertical(classes="panel-card"):
            yield Static("[bold]Screen Capture[/bold]", classes="card-title")
            yield Horizontal(
                Label("Save Dir:", classes="form-label"),
                Input(value=os.path.expanduser("~"), id="tool-cap-dir", classes="form-input"),
                classes="form-row"
            )
            yield Button("Capture Device Screen", variant="primary", id="btn-tool-screencap", classes="action-btn")


class SettingsScreen(Vertical):
    def compose(self) -> ComposeResult:
        cfg = Config()
        yield Static("[bold accent]Preferences & Settings[/bold accent]", classes="card-title")
        with Vertical(classes="panel-card"):
            yield Horizontal(
                Label("Default Path:", classes="form-label"),
                Input(value=cfg("default_path"), id="cfg-default-path", classes="form-input"),
                classes="form-row"
            )
            yield Horizontal(
                Label("Time Zone:", classes="form-label"),
                Input(value=cfg("time_zone"), id="cfg-time-zone", classes="form-input"),
                classes="form-row"
            )
            yield Horizontal(
                Label("Date Format:", classes="form-label"),
                Input(value=cfg("date_format"), id="cfg-date-format", classes="form-input"),
                classes="form-row"
            )
            yield Horizontal(
                Label("Custom Header:", classes="form-label"),
                Input(value=cfg("custom_header"), id="cfg-custom-header", classes="form-input"),
                classes="form-row"
            )
            yield Button("Save Configuration", variant="success", id="btn-save-cfg", classes="action-btn")


class ReportsScreen(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("[bold accent]Generated Reports Browser[/bold accent]", classes="card-title")
        yield Static("Recent reports will appear here after extraction.")
        yield ListView(id="reports-list")


class AndroidForensicTUI(App):
    """Textual Terminal User Interface for AndroidForensic Everywhere."""
    
    CSS_PATH = "styles.tcss"
    TITLE = f"{__app_name__} TUI v{__version__}"
    SUB_TITLE = "Modern Reactive Forensic Acquisition & Decoding"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "nav('dashboard')", "Dashboard"),
        ("e", "nav('extract')", "Extract"),
        ("c", "nav('decoders')", "Decoders"),
        ("l", "nav('lockscreen')", "Lockscreen"),
        ("t", "nav('tools')", "Tools"),
        ("s", "nav('settings')", "Settings"),
        ("r", "nav('reports')", "Reports"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Grid(id="app-grid"):
            with Vertical(id="sidebar"):
                yield Static("AndroidForensic\n[bold white]Everywhere[/bold white]", id="sidebar-title")
                yield ListView(
                    ListItem(Label(" [D] Dashboard "), id="nav-dashboard", classes="-selected"),
                    ListItem(Label(" [E] Extraction "), id="nav-extract"),
                    ListItem(Label(" [C] Decoders "), id="nav-decoders"),
                    ListItem(Label(" [L] Lockscreen "), id="nav-lockscreen"),
                    ListItem(Label(" [T] Tools "), id="nav-tools"),
                    ListItem(Label(" [S] Settings "), id="nav-settings"),
                    ListItem(Label(" [R] Reports "), id="nav-reports"),
                    id="nav-list"
                )
            
            with ScrollableContainer(id="main-content"):
                yield DashboardScreen(id="screen-dashboard")
                yield ExtractionScreen(id="screen-extract", classes="hidden")
                yield DecodersScreen(id="screen-decoders", classes="hidden")
                yield LockscreenScreen(id="screen-lockscreen", classes="hidden")
                yield ToolsScreen(id="screen-tools", classes="hidden")
                yield SettingsScreen(id="screen-settings", classes="hidden")
                yield ReportsScreen(id="screen-reports", classes="hidden")
                
            with Vertical(id="console-dock"):
                yield Static("System Log Console", id="console-title")
                yield ConsoleLog(id="console-log")
        yield Footer()
        
    def on_mount(self) -> None:
        self.current_screen_id = "dashboard"
        self.log_to_console(f"Initialized {__app_name__} TUI.", "green")
        
    def log_to_console(self, msg: str, style: str = "white") -> None:
        console_widget = self.query_one("#console-log", ConsoleLog)
        console_widget.log_message(msg, style=style)
        
    def action_nav(self, target: str) -> None:
        self.switch_screen_view(target)
        
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.item and event.item.id and event.item.id.startswith("nav-"):
            target = event.item.id.replace("nav-", "")
            self.switch_screen_view(target)
            
    def switch_screen_view(self, target: str) -> None:
        screens = ["dashboard", "extract", "decoders", "lockscreen", "tools", "settings", "reports"]
        if target not in screens:
            return
            
        for s in screens:
            widget = self.query_one(f"#screen-{s}")
            nav_item = self.query_one(f"#nav-{s}")
            if s == target:
                widget.remove_class("hidden")
                widget.styles.display = "block"
                nav_item.add_class("-selected")
            else:
                widget.add_class("hidden")
                widget.styles.display = "none"
                nav_item.remove_class("-selected")
        
        self.current_screen_id = target
        self.log_to_console(f"Switched view to {target.title()}.", "dim")

    # --- BUTTON CLICK HANDLERS ---
    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "quick-usb":
            self.switch_screen_view("extract")
        elif btn_id == "quick-crack":
            self.switch_screen_view("lockscreen")
        elif btn_id == "btn-start-usb":
            self.run_usb_extraction_worker()
        elif btn_id == "btn-crack-pattern":
            self.run_pattern_crack()
        elif btn_id == "btn-save-cfg":
            self.save_settings()
        elif btn_id == "btn-tool-ab2tar":
            self.run_ab2tar_worker()
        elif btn_id == "btn-tool-screencap":
            self.run_screencap()

    def run_usb_extraction_worker(self) -> None:
        out_dir = self.query_one("#usb-out-dir", Input).value
        shared = self.query_one("#usb-shared", Checkbox).value
        self.log_to_console(f"Starting USB Extraction to {out_dir} (Shared: {shared})...", "yellow")
        
        def status_cb(msg):
            self.call_from_thread(self.log_to_console, msg, "cyan")
            
        def work():
            try:
                ce = ChainExecution(base_dir=out_dir, status_msg=status_cb, use_adb=True, do_shared=shared)
                ce.InitialAdbRead()
                if not ce.REPORT.get("serial"):
                    status_cb("ERROR: No Android device detected!")
                    return
                ce.CreateWorkDir()
                status_cb("Acquiring data...")
                ce.DataAcquisition(shared=shared)
                status_cb("Extracting data...")
                ce.DataExtraction()
                if shared:
                    ce.DecodeShared()
                status_cb("Decoding databases...")
                ce.DataDecoding()
                status_cb("Generating reports...")
                ce.GenerateHtmlReport(open_html=False)
                ce.GenerateXlsxReport()
                ce.CleanUp()
                status_cb(f"SUCCESS! Report created in {ce.work_dir}")
            except Exception as e:
                status_cb(f"EXTRACTION FAILED: {e}")

        self.run_worker(work, thread=True)

    def run_pattern_crack(self) -> None:
        pat_hash = self.query_one("#pattern-hash-input", Input).value.strip()
        if not pat_hash:
            self.log_to_console("Please enter a pattern hash.", "red")
            return
        self.log_to_console(f"Cracking pattern hash {pat_hash}...", "yellow")
        res = crack_pattern(pat_hash)
        if res:
            self.log_to_console(f"PATTERN CRACKED: {' -> '.join(str(int(c)) for c in res)}", "bold green")
        else:
            self.log_to_console("Pattern cracking failed.", "red")

    def save_settings(self) -> None:
        cfg = Config()
        def_path = self.query_one("#cfg-default-path", Input).value
        tz = self.query_one("#cfg-time-zone", Input).value
        df = self.query_one("#cfg-date-format", Input).value
        ch = self.query_one("#cfg-custom-header", Input).value
        cfg.update_conf(**{cfg.NS: {
            "default_path": def_path,
            "time_zone": tz,
            "date_format": df,
            "custom_header": ch
        }})
        self.log_to_console("Configuration saved successfully!", "bold green")

    def run_ab2tar_worker(self) -> None:
        ab_path = self.query_one("#tool-ab-input", Input).value.strip()
        if not ab_path or not os.path.isfile(ab_path):
            self.log_to_console("Invalid AB file path.", "red")
            return
        self.log_to_console(f"Converting {ab_path} to TAR...", "yellow")
        
        def work():
            try:
                tar_path = DrillerTools.ab_to_tar(ab_path, to_tmp=False)
                self.call_from_thread(self.log_to_console, f"AB converted to TAR successfully: {tar_path}", "bold green")
            except Exception as e:
                self.call_from_thread(self.log_to_console, f"AB to TAR error: {e}", "red")
                
        self.run_worker(work, thread=True)

    def run_screencap(self) -> None:
        out_dir = self.query_one("#tool-cap-dir", Input).value.strip()
        self.log_to_console("Capturing screenshot via ADB...", "yellow")
        
        def work():
            from ..screencap import ScreenStore
            try:
                store = ScreenStore()
                store.set_output(out_dir)
                res = store.capture()
                if res:
                    self.call_from_thread(self.log_to_console, f"Screenshot saved! Report at: {store.report()}", "bold green")
                else:
                    self.call_from_thread(self.log_to_console, "Screenshot failed (no device or secure screen).", "red")
            except Exception as e:
                self.call_from_thread(self.log_to_console, f"Screencap error: {e}", "red")
                
        self.run_worker(work, thread=True)


if __name__ == "__main__":
    app = AndroidForensicTUI()
    app.run()
