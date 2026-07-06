import os
import time
import json
import queue
import threading
from pathlib import Path
from flask import Flask, render_template, jsonify, request, Response, send_from_directory

from .. import __version__, __app_name__
from ..config import Config
from ..adb_conn import ADBConn
from ..driller import ChainExecution
from ..cracking import crack_pattern, PasswordCrack
from ..utils import DrillerTools
from ..decoders import AndroidDecoder
from ..screencap import ScreenStore
from ..decrypts import WhatsAppCrypt7, WhatsAppCrypt8, WhatsAppCrypt12

# Global log queue for Server-Sent Events (SSE)
log_queue = queue.Queue()


def log_event(msg, level="info"):
    """Push log event to SSE queue."""
    timestamp = time.strftime("%H:%M:%S")
    log_queue.put(f"data: {json.dumps({'time': timestamp, 'msg': msg, 'level': level})}\n\n")


def create_app(test_config=None):
    """Create and configure Flask web application."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.urandom(24),
        DATABASE=os.path.join(app.instance_path, "androidforensic.sqlite"),
    )

    if test_config:
        app.config.from_mapping(test_config)

    # Ensure instance directory exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # --- HTML ROUTES ---
    @app.route("/")
    def index():
        return render_template("dashboard.html", version=__version__, app_name=__app_name__, active_page="dashboard")

    @app.route("/extract")
    def extract_page():
        default_dir = os.path.expanduser("~")
        return render_template("extract.html", default_dir=default_dir, active_page="extract")

    @app.route("/decoders")
    def decoders_page():
        dec_list = []
        for sub in AndroidDecoder.get_subclasses():
            if not sub.exclude_from_registry:
                dec_list.append({
                    "name": sub.__name__,
                    "target": str(sub.RETARGET or sub.TARGET),
                    "package": str(sub.PACKAGE or "System/Generic"),
                    "title": getattr(sub, "title", sub.__name__)
                })
        return render_template("decoders.html", decoders=dec_list, active_page="decoders")

    @app.route("/crack")
    def crack_page():
        return render_template("lockscreen.html", active_page="crack")

    @app.route("/tools")
    def tools_page():
        default_dir = os.path.expanduser("~")
        return render_template("tools.html", default_dir=default_dir, active_page="tools")

    @app.route("/settings")
    def settings_page():
        cfg = Config()
        return render_template("settings.html", conf=cfg.conf[cfg.NS], active_page="settings")

    @app.route("/reports")
    def reports_page():
        cfg = Config()
        base_dir = cfg("default_path") or os.path.expanduser("~")
        reports = []
        if os.path.exists(base_dir):
            for root, dirs, files in os.walk(base_dir):
                if "REPORT.html" in files:
                    rep_path = os.path.join(root, "REPORT.html")
                    stat = os.stat(rep_path)
                    reports.append({
                        "name": os.path.basename(root),
                        "path": rep_path,
                        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                        "size": round(stat.st_size / 1024, 2)
                    })
        reports.sort(key=lambda x: x["time"], reverse=True)
        return render_template("reports.html", reports=reports, active_page="reports")

    @app.route("/reports/view")
    def view_report_file():
        path = request.args.get("path")
        if path and os.path.isfile(path) and "REPORT.html" in path:
            return send_from_directory(os.path.dirname(path), os.path.basename(path))
        return "Report file not found or unauthorized.", 404

    # --- API ENDPOINTS ---
    @app.route("/api/device/status")
    def api_device_status():
        try:
            adb = ADBConn()
            serial, status = adb.device()
            if serial:
                priv = "shell"
                try:
                    out = adb.adb_out("id")
                    if "uid=0(root)" in out:
                        priv = "root"
                except Exception:
                    pass
                return jsonify({"connected": True, "serial": serial, "status": status, "privilege": priv})
            return jsonify({"connected": False, "serial": "No Device", "status": "disconnected", "privilege": "-"})
        except Exception as e:
            return jsonify({"connected": False, "error": str(e)}), 500

    @app.route("/api/device/reboot", methods=["POST"])
    def api_device_reboot():
        data = request.get_json() or {}
        mode = data.get("mode", "normal")
        try:
            adb = ADBConn()
            adb.reboot(None if mode == "normal" else mode)
            log_event(f"Sent reboot command ({mode}) to device.", "warning")
            return jsonify({"success": True, "message": f"Rebooting device into {mode} mode..."})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/extract/start", methods=["POST"])
    def api_extract_start():
        data = request.get_json() or {}
        mode = data.get("mode", "usb")
        output_dir = data.get("output_dir") or os.path.expanduser("~")
        shared = data.get("shared", False)
        src_path = data.get("src_path")

        def run_extraction_thread():
            log_event(f"Starting {mode.upper()} acquisition/parsing...", "info")
            try:
                def status_cb(msg):
                    log_event(msg, "info")

                if mode == "usb":
                    ce = ChainExecution(base_dir=output_dir, status_msg=status_cb, use_adb=True, do_shared=shared)
                    ce.InitialAdbRead()
                    if not ce.REPORT.get("serial"):
                        log_event("Extraction failed: No Android device detected over ADB.", "error")
                        return
                    ce.CreateWorkDir()
                    ce.DataAcquisition(shared=shared)
                    ce.DataExtraction()
                    if shared:
                        ce.DecodeShared()
                    ce.DataDecoding()
                    ce.GenerateHtmlReport(open_html=False)
                    ce.GenerateXlsxReport()
                    ce.CleanUp()
                elif mode == "folder":
                    ce = ChainExecution(base_dir=output_dir, status_msg=status_cb, use_adb=False, src_dir=src_path)
                    ce.REPORT = {"serial": "Folder_Extraction", "permisson": "offline"}
                    ce.CreateWorkDir()
                    ce.ExtractFromDir()
                    ce.DataDecoding()
                    ce.GenerateHtmlReport(open_html=False)
                    ce.GenerateXlsxReport()
                    ce.CleanUp()
                elif mode == "ab":
                    ce = ChainExecution(base_dir=output_dir, status_msg=status_cb, use_adb=False, backup=src_path)
                    ce.REPORT = {"serial": "AB_Backup", "permisson": "offline"}
                    ce.CreateWorkDir()
                    ce.DataExtraction()
                    ce.DataDecoding()
                    ce.GenerateHtmlReport(open_html=False)
                    ce.GenerateXlsxReport()
                    ce.CleanUp()

                log_event("Extraction & decoding completed successfully!", "success")
            except Exception as e:
                log_event(f"Error during extraction: {str(e)}", "error")

        threading.Thread(target=run_extraction_thread, daemon=True).start()
        return jsonify({"success": True, "message": f"Started {mode} extraction background task."})

    @app.route("/api/crack/pattern", methods=["POST"])
    def api_crack_pattern():
        data = request.get_json() or {}
        pat_hash = data.get("hash", "").strip()
        if not pat_hash:
            return jsonify({"success": False, "error": "Empty pattern hash provided."}), 400
        
        log_event(f"Attempting pattern crack for hash: {pat_hash[:16]}...", "info")
        res = crack_pattern(pat_hash)
        if res:
            seq_str = " -> ".join(str(int(c)) for c in res)
            log_event(f"Pattern cracked successfully: {seq_str}", "success")
            return jsonify({"success": True, "pattern": seq_str, "sequence": [int(c) for c in res]})
        return jsonify({"success": False, "error": "Pattern not found or invalid hash."})

    @app.route("/api/crack/pin", methods=["POST"])
    def api_crack_pin():
        data = request.get_json() or {}
        hash_val = data.get("hash", "").strip()
        salt_val = int(data.get("salt", 0))
        max_len = int(data.get("max_len", 8))
        samsung = data.get("samsung", False)

        def run_pin_thread():
            log_event(f"Starting PIN crack (Max Len: {max_len}, Samsung algorithm: {samsung})...", "info")
            try:
                cracker = PasswordCrack(key=hash_val, salt=salt_val, end=10**max_len - 1, samsung=samsung)
                
                def cb(pin):
                    if int(pin) % 5000 == 0:
                        log_event(f"Trying PIN: {pin} (Rate: {cracker.rate} keys/s)", "info")

                res = cracker.crack_password(callback=cb)
                if res:
                    log_event(f"PIN CRACKED SUCCESSFULLY: {res}", "success")
                else:
                    log_event("PIN cracking finished. No match found in range.", "warning")
            except Exception as e:
                log_event(f"PIN cracking error: {str(e)}", "error")

        threading.Thread(target=run_pin_thread, daemon=True).start()
        return jsonify({"success": True, "message": "PIN cracking started in background."})

    @app.route("/api/tools/ab2tar", methods=["POST"])
    def api_tools_ab2tar():
        data = request.get_json() or {}
        ab_path = data.get("ab_path", "").strip()
        if not ab_path or not os.path.isfile(ab_path):
            return jsonify({"success": False, "error": "Invalid AB file path."}), 400

        def run_ab2tar_thread():
            log_event(f"Converting AB to TAR: {ab_path}", "info")
            try:
                tar_path = DrillerTools.ab_to_tar(ab_path, to_tmp=False)
                log_event(f"Converted successfully to TAR: {tar_path}", "success")
            except Exception as e:
                log_event(f"AB2TAR conversion failed: {str(e)}", "error")

        threading.Thread(target=run_ab2tar_thread, daemon=True).start()
        return jsonify({"success": True, "message": "AB to TAR conversion started."})

    @app.route("/api/tools/screencap", methods=["POST"])
    def api_tools_screencap():
        data = request.get_json() or {}
        out_dir = data.get("out_dir") or os.path.expanduser("~")
        note = data.get("note", "")

        def run_cap_thread():
            log_event("Capturing Android screen via ADB...", "info")
            try:
                store = ScreenStore()
                store.set_output(out_dir)
                res = store.capture(note=note)
                if res:
                    log_event(f"Screenshot saved successfully! Report: {store.report()}", "success")
                else:
                    log_event("Screen capture failed. Ensure device screen is unlocked and not secure.", "error")
            except Exception as e:
                log_event(f"Screenshot error: {str(e)}", "error")

        threading.Thread(target=run_cap_thread, daemon=True).start()
        return jsonify({"success": True, "message": "Screen capture initiated."})

    @app.route("/api/config/save", methods=["POST"])
    def api_config_save():
        data = request.get_json() or {}
        cfg = Config()
        cfg.update_conf(**{cfg.NS: data})
        log_event("Application configuration saved.", "success")
        return jsonify({"success": True, "message": "Settings updated."})

    @app.route("/api/logs/stream")
    def api_logs_stream():
        """Server-Sent Events (SSE) log streaming endpoint."""
        def stream():
            while True:
                try:
                    msg = log_queue.get(timeout=20)
                    yield msg
                except queue.Empty:
                    yield "data: {\"time\": \"\", \"msg\": \"ping\", \"level\": \"ping\"}\n\n"
        return Response(stream(), mimetype="text/event-stream")

    return app
