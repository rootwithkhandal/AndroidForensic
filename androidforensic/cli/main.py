import os
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .. import __version__, __app_name__
from ..config import Config
from ..adb_conn import ADBConn, ADBConnError
from ..driller import ChainExecution
from ..cracking import crack_pattern, PasswordCrack
from ..decrypts import WhatsAppCrypt7, WhatsAppCrypt8, WhatsAppCrypt12, WhatsAppCryptError
from ..statics import GUIDE_WA

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name=__app_name__)
def cli():
    """AndroidForensic Everywhere - Multi-interface Android Forensic Toolkit."""
    pass


@cli.command()
@click.option("--port", default=5000, help="Port to run the web server on.")
@click.option("--host", default="127.0.0.1", help="Host interface to bind to.")
@click.option("--debug/--no-debug", default=False, help="Enable Flask debug mode.")
def gui(port, host, debug):
    """Launch the responsive Web-based GUI (Flask)."""
    console.print(f"[bold cyan]Starting {__app_name__} Web GUI...[/bold cyan]")
    from ..web.app import create_app
    app = create_app()
    app.run(host=host, port=port, debug=debug)


@cli.command()
def tui():
    """Launch the Terminal User Interface (Textual)."""
    from ..tui.app import AndroidForensicTUI
    app = AndroidForensicTUI()
    app.run()


# --- DEVICE MANAGEMENT ---
@cli.group()
def device():
    """Manage connected Android devices via ADB."""
    pass


@device.command("status")
def device_status():
    """Check connection status of attached Android devices."""
    try:
        adb = ADBConn()
        serial, status = adb.device()
        if serial:
            table = Table(title="Connected Device Status", style="cyan")
            table.add_column("Property", style="bold yellow")
            table.add_column("Value", style="green")
            table.add_row("Serial Number", serial)
            table.add_row("State", status)
            
            # Get extra properties
            root_status = adb.adb_out("id")
            table.add_row("Privilege Level", "root" if "uid=0(root)" in root_status else "shell (non-root)")
            console.print(table)
        else:
            console.print("[bold red]No device detected or unauthorized.[/bold red]")
            console.print("Please check USB connection, enable USB debugging, and authorize RSA fingerprint.")
    except Exception as e:
        console.print(f"[bold red]Error checking device status:[/bold red] {e}")


@device.command("reboot")
@click.argument("mode", default="normal", type=click.Choice(["normal", "bootloader", "recovery", "download"]))
def device_reboot(mode):
    """Reboot the connected device into specified mode."""
    try:
        adb = ADBConn()
        serial, _ = adb.device()
        if not serial:
            console.print("[bold red]No device connected.[/bold red]")
            return
        
        console.print(f"[yellow]Rebooting device {serial} into mode: [bold]{mode}[/bold]...[/yellow]")
        adb.reboot(None if mode == "normal" else mode)
        console.print("[bold green]Reboot command issued.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Reboot failed:[/bold red] {e}")


# --- EXTRACTION SUBCOMMANDS ---
@cli.group()
def extract():
    """Perform data acquisition and extraction from devices or backups."""
    pass


@extract.command("usb")
@click.option("--output", "-o", default=os.path.expanduser("~"), help="Output destination directory.")
@click.option("--shared/--no-shared", default=False, help="Include shared storage (SD card / internal storage).")
def extract_usb(output, shared):
    """Acquire forensic data directly from a connected USB device."""
    console.print(Panel(f"[bold cyan]USB Forensic Acquisition[/bold cyan]\nOutput: {output}", expand=False))
    try:
        def status_cb(msg):
            console.print(f"[cyan]>[/cyan] {msg}")

        ce = ChainExecution(base_dir=output, status_msg=status_cb, use_adb=True, do_shared=shared)
        ce.InitialAdbRead()
        if not ce.REPORT.get("serial"):
            console.print("[bold red]No Android device detected! Aborting.[/bold red]")
            return

        ce.CreateWorkDir()
        console.print(f"[green]Created workspace:[/green] {ce.work_dir}")

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Acquiring device data...", total=None)
            ce.DataAcquisition(shared=shared)
            progress.update(task, description="Extracting acquired data...")
            ce.DataExtraction()
            if shared:
                progress.update(task, description="Decoding shared storage...")
                ce.DecodeShared()
            progress.update(task, description="Decoding databases...")
            ce.DataDecoding()
            progress.update(task, description="Generating reports...")
            ce.GenerateHtmlReport(open_html=False)
            ce.GenerateXlsxReport()
            ce.CleanUp()
        
        console.print(f"[bold green]Extraction Complete![/bold green] Report generated at: {os.path.join(ce.base_dir, ce.work_dir, 'REPORT.html')}")
    except Exception as e:
        console.print(f"[bold red]Extraction failed:[/bold red] {e}")


@extract.command("folder")
@click.argument("folder_path", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", default=os.path.expanduser("~"), help="Output destination directory.")
def extract_folder(folder_path, output):
    """Parse and decode an existing data folder (e.g. /data/data extraction)."""
    console.print(f"[bold cyan]Folder Parsing:[/bold cyan] {folder_path}")
    try:
        def status_cb(msg):
            console.print(f"[cyan]>[/cyan] {msg}")

        ce = ChainExecution(base_dir=output, status_msg=status_cb, use_adb=False, src_dir=folder_path)
        ce.REPORT = {"serial": "Folder_Extraction", "permisson": "offline"}
        ce.CreateWorkDir()

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Extracting recognized databases...", total=None)
            ce.ExtractFromDir()
            progress.update(task, description="Decoding databases...")
            ce.DataDecoding()
            progress.update(task, description="Generating reports...")
            ce.GenerateHtmlReport(open_html=False)
            ce.GenerateXlsxReport()
            ce.CleanUp()

        console.print(f"[bold green]Parsing Complete![/bold green] Report: {os.path.join(ce.base_dir, ce.work_dir, 'REPORT.html')}")
    except Exception as e:
        console.print(f"[bold red]Folder extraction failed:[/bold red] {e}")


@extract.command("ab")
@click.argument("ab_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", default=os.path.expanduser("~"), help="Output destination directory.")
def extract_ab(ab_file, output):
    """Parse and decode an Android Backup (.ab) file."""
    console.print(f"[bold cyan]AB File Parsing:[/bold cyan] {ab_file}")
    try:
        def status_cb(msg):
            console.print(f"[cyan]>[/cyan] {msg}")

        ce = ChainExecution(base_dir=output, status_msg=status_cb, use_adb=False, backup=ab_file)
        ce.REPORT = {"serial": "AB_Backup", "permisson": "offline"}
        ce.CreateWorkDir()

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Converting AB to TAR and extracting...", total=None)
            ce.DataExtraction()
            progress.update(task, description="Decoding databases...")
            ce.DataDecoding()
            progress.update(task, description="Generating reports...")
            ce.GenerateHtmlReport(open_html=False)
            ce.GenerateXlsxReport()
            ce.CleanUp()

        console.print(f"[bold green]AB Parsing Complete![/bold green] Report: {os.path.join(ce.base_dir, ce.work_dir, 'REPORT.html')}")
    except Exception as e:
        console.print(f"[bold red]AB parsing failed:[/bold red] {e}")


# --- CRACKING SUBCOMMANDS ---
@cli.group()
def crack():
    """Crack Android lockscreen gesture patterns and PIN/passwords."""
    pass


@crack.command("pattern")
@click.argument("pattern_hash")
def crack_pattern_cmd(pattern_hash):
    """Crack a gesture pattern from its hex hash or gesture.key file."""
    if os.path.isfile(pattern_hash):
        with open(pattern_hash, "rb") as f:
            pattern_hash = f.read().hex()
    
    console.print(f"[yellow]Attempting to crack pattern hash:[/yellow] {pattern_hash}")
    res = crack_pattern(pattern_hash)
    if res:
        console.print(f"[bold green]SUCCESS![/bold green] Pattern sequence: [bold cyan]{' -> '.join(str(int(c)) for c in res)}[/bold cyan]")
    elif res is None:
        console.print("[yellow]Empty pattern hash (no screen lock set).[/yellow]")
    else:
        console.print("[bold red]Failed to crack gesture pattern.[/bold red]")


@crack.command("pin")
@click.argument("hash_val")
@click.argument("salt_val", type=int)
@click.option("--max-len", default=8, help="Maximum PIN length to try.")
@click.option("--samsung/--no-samsung", default=False, help="Use Samsung specific SHA1/PBKDF algorithm.")
def crack_pin_cmd(hash_val, salt_val, max_len, samsung):
    """Crack a numeric PIN given hash and integer salt."""
    console.print(f"[yellow]Cracking PIN (Max Len: {max_len}, Samsung: {samsung})...[/yellow]")
    try:
        cracker = PasswordCrack(key=hash_val, salt=salt_val, end=10**max_len - 1, samsung=samsung)
        
        def ui_cb(pin):
            console.print(f"[dim]Trying:[/dim] {pin} (Rate: {cracker.rate} keys/sec)", end="\r")

        result = cracker.crack_password(callback=ui_cb)
        if result:
            console.print(f"\n[bold green]SUCCESS! PIN FOUND:[/bold green] [bold cyan]{result}[/bold cyan]")
        else:
            console.print("\n[bold red]PIN not found in specified range.[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Cracking error:[/bold red] {e}")


# --- TOOLS SUBCOMMANDS ---
@cli.group()
def tools():
    """Auxiliary forensic utilities (AB to TAR, Screen capture, WhatsApp decryption)."""
    pass


@tools.command("ab2tar")
@click.argument("ab_file", type=click.Path(exists=True, dir_okay=False))
def tools_ab2tar(ab_file):
    """Convert an Android Backup (.ab) file to a standard .tar archive."""
    from ..utils import DrillerTools
    console.print(f"[cyan]Converting {ab_file} to TAR...[/cyan]")
    try:
        tar_path = DrillerTools.ab_to_tar(ab_file, to_tmp=False)
        console.print(f"[bold green]Success![/bold green] Created TAR archive at: [bold]{tar_path}[/bold]")
    except Exception as e:
        console.print(f"[bold red]Conversion failed:[/bold red] {e}")


@tools.command("screencap")
@click.option("--output", "-o", default=os.path.expanduser("~"), help="Directory to save screen captures.")
@click.option("--note", default="", help="Note/comment to attach to this screenshot.")
def tools_screencap(output, note):
    """Capture a screenshot from a connected device via ADB."""
    from ..screencap import ScreenStore
    try:
        store = ScreenStore()
        store.set_output(output)
        res = store.capture(note=note)
        if res:
            console.print(f"[bold green]Screenshot saved![/bold green] Total captures: {store.count}")
            report_path = store.report()
            console.print(f"[cyan]Screencap report updated at:[/cyan] {report_path}")
        else:
            console.print("[bold red]Failed to capture screen.[/bold red] Ensure device is connected and screen is not protected (FLAG_SECURE).")
    except Exception as e:
        console.print(f"[bold red]Screencap error:[/bold red] {e}")


@tools.command("wa-decrypt")
@click.argument("crypt_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("key_file", type=click.Path(exists=True, dir_okay=False))
def tools_wa_decrypt(crypt_file, key_file):
    """Decrypt WhatsApp crypt7/8/12 database using extracted key file."""
    console.print(f"[cyan]Decrypting WhatsApp database:[/cyan] {crypt_file} [dim]using key:[/dim] {key_file}")
    try:
        ext = os.path.splitext(crypt_file)[1].lower()
        if ext == ".crypt12":
            decryptor = WhatsAppCrypt12(crypt_file, key_file)
        elif ext == ".crypt8":
            decryptor = WhatsAppCrypt8(crypt_file, key_file)
        elif ext == ".crypt7":
            decryptor = WhatsAppCrypt7(crypt_file, key_file)
        else:
            console.print(f"[bold red]Unsupported WhatsApp crypt extension: {ext}[/bold red]")
            return

        out_path = decryptor.decrypt()
        console.print(f"[bold green]Decryption successful![/bold green] SQLite database written to: [bold]{out_path}[/bold]")
    except Exception as e:
        console.print(f"[bold red]Decryption failed:[/bold red] {e}")


# --- CONFIG SUBCOMMANDS ---
@cli.group()
def config():
    """View and modify AndroidForensic Everywhere settings."""
    pass


@config.command("show")
def config_show():
    """Show current application settings."""
    cfg = Config()
    table = Table(title="AndroidForensic Everywhere Configuration", style="cyan")
    table.add_column("Key", style="bold yellow")
    table.add_column("Value", style="green")
    
    for k, v in cfg.conf[cfg.NS].items():
        table.add_row(k, str(v))
    
    console.print(table)
    console.print(f"[dim]Config file located at: {cfg.config_file}[/dim]")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a configuration parameter."""
    cfg = Config()
    if key not in cfg.conf[cfg.NS]:
        console.print(f"[bold red]Unknown configuration key: {key}[/bold red]")
        return
    
    cfg.update_conf(**{cfg.NS: {key: value}})
    console.print(f"[bold green]Updated {key} -> {value}[/bold green]")


@config.command("reset")
def config_reset():
    """Reset configuration to default values."""
    cfg = Config()
    cfg.initialise()
    console.print("[bold green]Configuration reset to default values.[/bold green]")


if __name__ == "__main__":
    cli()
