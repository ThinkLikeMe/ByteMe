
APP_VERSION = "1.0.2"

import requests
import shlex
import tempfile
import shutil
import tarfile
import os
import subprocess

from packaging import version
from datetime import datetime
from PyQt5 import QtWidgets, QtCore, QtGui
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─────────────────────────────────────────────────────────────────────────────
# 1) Helper for macOS notifications via AppleScript (so it appears in the
#    Notification Center instead of a blocking QMessageBox).
def send_notification(title: str, message: str):
    """
    Display a macOS Notification Center notification with given title & message.
    """
    try:
        # Escape quotes in message
        safe_title = title.replace('"', '\\"')
        safe_message = message.replace('"', '\\"')
        script = f'display notification "{safe_message}" with title "{safe_title}"'
        subprocess.run(["osascript", "-e", script], check=False)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Paths for settings, logs, and quarantine metadata:
SETTINGS_PATH = os.path.expanduser("~/.byteme_settings.json")
LOG_FILE_PATH = os.path.expanduser("~/.byteme.log")
QUARANTINE_FOLDER = os.path.expanduser(
    "~/Library/Application Support/ByteMe/Quarantine"
)
QUARANTINE_METADATA_PATH = os.path.expanduser("~/.byteme_quarantine.json")


def query_osv(app_name: str, version: str) -> list:
    """
    Query OSV for a given package name + version.
    Returns a list of OSV vulnerability dicts (or an empty list).
    """
    payload = {
        "package": {
            "name": app_name.lower(),
            "ecosystem": "Homebrew"
        },
        "version": version
    }
    try:
        resp = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("vulns", [])
    except Exception:
        pass
    return []


class FileChangeHandler(FileSystemEventHandler):
    """
    Watches for new files in a directory (or drive) and triggers a callback.
    """
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self.callback(event.src_path)


class ByteMeWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        # Make sure the app does NOT quit when the window is closed:
        QtWidgets.QApplication.setQuitOnLastWindowClosed(False)

        self.setWindowTitle("ByteMe")
        self.setGeometry(100, 100, 1000, 700)
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0b1e3f;
                color: #ffd700;
                font-family: Arial;
                font-size: 14px;
            }
            QPushButton {
                background-color: #13294b;
                color: #ffd700;
                border: 1px solid #ffd700;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0f233c;
            }
            QTextEdit, QLineEdit, QSpinBox, QListWidget {
                background-color: #13294b;
                color: #ffd700;
                border: 1px solid #ffd700;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #ffd700;
            }
            QTabBar::tab {
                background: #0b1e3f;
                color: #ffd700;
                padding: 10px;
                border: 1px solid #ffd700;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #13294b;
                font-weight: bold;
            }
        """)

        # Ensure quarantine folder and log files exist
        os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
        open(LOG_FILE_PATH, "a").close()
        if not os.path.exists(QUARANTINE_METADATA_PATH):
            with open(QUARANTINE_METADATA_PATH, "w") as f:
                json.dump([], f)

        # Load settings and quarantine metadata
        self.settings = self.load_settings()
        self.api_key = self.settings.get("api_key", "")
        self.otx_api_key = self.settings.get("otx_api_key", "")
        self.scan_interval_minutes = self.settings.get("scan_interval_minutes", 0)
        self.quarantine_list_data = self.load_quarantine_metadata()

        # Default scan folder (for manual scans)
        self.scan_folder = os.path.expanduser("~/Documents")

        # Build the UI
        self.init_ui()

        # Start monitoring the Downloads folder only
        self.start_drive_monitor()

        # If scan interval > 0, start the timer for scheduled vulnerability scans
        if self.scan_interval_minutes > 0:
            self.timer = QtCore.QTimer(self)
            self.timer.timeout.connect(self.run_vulnerability_scan)
            self.timer.start(self.scan_interval_minutes * 60 * 1000)

        # Create the tray icon so the app can keep running when window is closed
        self.create_tray_icon()

    def load_settings(self):
        """
        Load settings from disk:
        {
          "api_key": "<VT API key>",
          "otx_api_key": "<OTX API key>",
          "scan_interval_minutes": <int>
        }
        """
        if os.path.exists(SETTINGS_PATH):
            try:
                with open(SETTINGS_PATH, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"api_key": "", "otx_api_key": "", "scan_interval_minutes": 0}

    def save_settings(self):
        """
        Persist self.api_key, self.otx_api_key, and self.scan_interval_minutes.
        """
        data = {
            "api_key": self.api_key,
            "otx_api_key": self.otx_api_key,
            "scan_interval_minutes": self.scan_interval_minutes
        }
        try:
            with open(SETTINGS_PATH, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            QtWidgets.QMessageBox.warning(
                self, "Error Saving Settings", f"Could not save settings:\n{e}"
            )

    def load_quarantine_metadata(self):
        """
        Load the list of quarantined items from JSON file.
        Returns a list of dicts:
        [
          {
            "original_path": "...",
            "quarantine_path": "...",
            "timestamp": "YYYY-MM-DD HH:MM:SS"
          },
          ...
        ]
        """
        try:
            with open(QUARANTINE_METADATA_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def save_quarantine_metadata(self):
        """
        Write the current quarantine list data back to JSON file.
        """
        try:
            with open(QUARANTINE_METADATA_PATH, "w") as f:
                json.dump(self.quarantine_list_data, f, indent=2)
        except Exception:
            pass

    def init_ui(self):
        """
        Build main tabs:
          1. File Scan
          2. Lookups (Hash, URL, Domain)
          3. Settings
          4. Vulnerability (Search CVEs + Scan System)
          5. Quarantine (Items + Logs)
          6. Logs

        Also add a high-resolution yellow download-arrow icon at the top right.
        """
        # ── Add a toolbar with “Updates” at the top ───────────────────────────────────────────
        self.toolbar = self.addToolBar("MainToolbar")
        self.toolbar.setMovable(False)

        # Create a spacer so that the update icon is pushed to the right
        spacer = QtWidgets.QWidget()
        spacer.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        # ── Draw the download arrow at 64×64 and let Qt scale it down to 24×24 ────────────────
        big_size = 64
        big_pixmap = QtGui.QPixmap(big_size, big_size)
        big_pixmap.fill(QtCore.Qt.transparent)

        painter = QtGui.QPainter(big_pixmap)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.setRenderHint(QtGui.QPainter.HighQualityAntialiasing)

        pen = QtGui.QPen(QtGui.QColor("#ffd700"))
        pen.setWidth(4)  # Slightly thicker for 64×64
        painter.setPen(pen)
        painter.setBrush(QtCore.Qt.NoBrush)

        # Draw circle outline (center at 32,32, radius 28)
        painter.drawEllipse(QtCore.QPointF(big_size / 2, big_size / 2), 28, 28)

        # Draw arrow shaft
        painter.setPen(pen)
        shaft_top = QtCore.QPointF(big_size / 2, big_size * 0.15)
        shaft_bottom = QtCore.QPointF(big_size / 2, big_size * 0.4)
        painter.drawLine(shaft_top, shaft_bottom)

        # Draw arrow head (filled yellow triangle)
        arrow_head = [
            QtCore.QPointF(big_size / 2 - 10, big_size * 0.38),
            QtCore.QPointF(big_size / 2 + 10, big_size * 0.38),
            QtCore.QPointF(big_size / 2, big_size * 0.55)
        ]
        brush = QtGui.QBrush(QtGui.QColor("#ffd700"))
        painter.setBrush(brush)
        painter.drawPolygon(QtGui.QPolygonF(arrow_head))

        # Draw the bar at bottom of arrow (yellow line)
        painter.setBrush(QtCore.Qt.NoBrush)
        painter.setPen(pen)
        painter.drawLine(
            QtCore.QPointF(big_size / 2 - 14, big_size * 0.7),
            QtCore.QPointF(big_size / 2 + 14, big_size * 0.7)
        )

        painter.end()

        # Create a 24×24 icon from the 64×64 pixmap (Qt will scale down smoothly)
        small_pixmap = big_pixmap.scaled(
            24, 24,
            QtCore.Qt.KeepAspectRatio,
            QtCore.Qt.SmoothTransformation
        )

        update_icon = QtGui.QIcon(small_pixmap)
        self.update_action = QtWidgets.QAction(update_icon, "Check for Updates", self)
        self.update_action.triggered.connect(self.on_check_updates)
        self.toolbar.addAction(self.update_action)
        # ─────────────────────────────────────────────────────────────────────────────────────

        self.tabs = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tabs)

        # --- 1) File Scan ---
        self.scan_tab = QtWidgets.QWidget()
        scan_layout = QtWidgets.QVBoxLayout()

        self.folder_input = QtWidgets.QLineEdit(self.scan_folder)
        self.folder_input.setPlaceholderText("Select folder or file to scan…")
        scan_layout.addWidget(self.folder_input)

        self.folder_browse = QtWidgets.QPushButton("Browse File/Folder")
        self.folder_browse.clicked.connect(self.browse_folder)
        scan_layout.addWidget(self.folder_browse)

        self.scan_folder_button = QtWidgets.QPushButton("Scan Folder/File")
        self.scan_folder_button.clicked.connect(self.recursive_scan)
        scan_layout.addWidget(self.scan_folder_button)

        self.scan_result = QtWidgets.QTextEdit()
        scan_layout.addWidget(self.scan_result)

        self.scan_tab.setLayout(scan_layout)
        self.tabs.addTab(self.scan_tab, "File Scan")

        # --- 2) Lookups (Hash, URL, Domain) ---
        self.lookup_tab = QtWidgets.QWidget()
        lookup_layout = QtWidgets.QVBoxLayout(self.lookup_tab)

        self.lookup_subtabs = QtWidgets.QTabWidget()
        lookup_layout.addWidget(self.lookup_subtabs)

        # Hash Lookup
        self.hash_tab = QtWidgets.QWidget()
        hash_layout = QtWidgets.QVBoxLayout()
        self.hash_input = QtWidgets.QLineEdit()
        self.hash_input.setPlaceholderText("Enter file hash (SHA-256)…")
        hash_layout.addWidget(self.hash_input)
        self.hash_scan_button = QtWidgets.QPushButton("Lookup Hash")
        self.hash_scan_button.clicked.connect(self.scan_hash)
        hash_layout.addWidget(self.hash_scan_button)
        self.hash_result = QtWidgets.QTextEdit()
        hash_layout.addWidget(self.hash_result)
        self.hash_tab.setLayout(hash_layout)
        self.lookup_subtabs.addTab(self.hash_tab, "Hash Lookup")

        # URL Lookup
        self.url_tab = QtWidgets.QWidget()
        url_layout = QtWidgets.QVBoxLayout()
        self.url_input = QtWidgets.QLineEdit()
        self.url_input.setPlaceholderText("Enter URL to scan…")
        url_layout.addWidget(self.url_input)
        self.url_scan_button = QtWidgets.QPushButton("Scan URL")
        self.url_scan_button.clicked.connect(self.scan_url)
        url_layout.addWidget(self.url_scan_button)
        self.url_result = QtWidgets.QTextEdit()
        url_layout.addWidget(self.url_result)
        self.url_tab.setLayout(url_layout)
        self.lookup_subtabs.addTab(self.url_tab, "URL Lookup")

        # Domain Lookup
        self.domain_tab = QtWidgets.QWidget()
        domain_layout = QtWidgets.QVBoxLayout()
        self.domain_input = QtWidgets.QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain to lookup…")
        domain_layout.addWidget(self.domain_input)
        self.domain_scan_button = QtWidgets.QPushButton("Lookup Domain")
        self.domain_scan_button.clicked.connect(self.scan_domain)
        domain_layout.addWidget(self.domain_scan_button)
        self.domain_result = QtWidgets.QTextEdit()
        domain_layout.addWidget(self.domain_result)
        self.domain_tab.setLayout(domain_layout)
        self.lookup_subtabs.addTab(self.domain_tab, "Domain Lookup")

        self.tabs.addTab(self.lookup_tab, "Lookups")

        # --- 3) Settings ---
        self.settings_tab = QtWidgets.QWidget()
        settings_layout = QtWidgets.QFormLayout()
        self.api_key_input = QtWidgets.QLineEdit(self.api_key)
        self.api_key_input.setEchoMode(QtWidgets.QLineEdit.Password)
        settings_layout.addRow("VirusTotal API Key:", self.api_key_input)
        self.otx_api_key_input = QtWidgets.QLineEdit(self.otx_api_key)
        self.otx_api_key_input.setEchoMode(QtWidgets.QLineEdit.Password)
        settings_layout.addRow("OTX API Key:", self.otx_api_key_input)
        self.interval_input = QtWidgets.QSpinBox()
        self.interval_input.setMinimum(0)
        self.interval_input.setMaximum(1440)
        self.interval_input.setValue(self.scan_interval_minutes)
        settings_layout.addRow("Scan Interval (minutes):", self.interval_input)
        self.save_settings_button = QtWidgets.QPushButton("Save Settings")
        self.save_settings_button.clicked.connect(self.on_save_settings)
        settings_layout.addRow("", self.save_settings_button)
        self.settings_tab.setLayout(settings_layout)
        self.tabs.addTab(self.settings_tab, "Settings")

        # --- 4) Vulnerability (Search CVEs + Scan System) ---
        self.add_vulnerability_tab()

        # --- 5) Quarantine (Items + Logs) ---
        self.quarantine_tab = QtWidgets.QWidget()
        self.quarantine_tabs = QtWidgets.QTabWidget()

        # Sub-tab: Current Quarantined Items
        self.quarantine_items_tab = QtWidgets.QWidget()
        items_layout = QtWidgets.QVBoxLayout()
        self.quarantine_list = QtWidgets.QListWidget()
        items_layout.addWidget(self.quarantine_list)

        btn_layout = QtWidgets.QHBoxLayout()
        self.allow_button = QtWidgets.QPushButton("Allow")
        self.allow_button.clicked.connect(self.allow_quarantined_item)
        btn_layout.addWidget(self.allow_button)
        self.remove_button = QtWidgets.QPushButton("Remove")
        self.remove_button.clicked.connect(self.remove_quarantined_item)
        btn_layout.addWidget(self.remove_button)
        items_layout.addLayout(btn_layout)

        self.quarantine_items_tab.setLayout(items_layout)
        self.quarantine_tabs.addTab(self.quarantine_items_tab, "Items")

        # Sub-tab: Quarantine Logs
        self.quarantine_logs_tab = QtWidgets.QWidget()
        logs_layout = QtWidgets.QVBoxLayout()
        self.quarantine_log_list = QtWidgets.QListWidget()
        logs_layout.addWidget(self.quarantine_log_list)
        self.quarantine_logs_tab.setLayout(logs_layout)
        self.quarantine_tabs.addTab(self.quarantine_logs_tab, "Logs")

        quarantine_parent_layout = QtWidgets.QVBoxLayout()
        quarantine_parent_layout.addWidget(self.quarantine_tabs)
        self.quarantine_tab.setLayout(quarantine_parent_layout)
        self.tabs.addTab(self.quarantine_tab, "Quarantine")

        # --- 6) Main Logs ---
        self.logs_tab = QtWidgets.QWidget()
        main_logs_layout = QtWidgets.QVBoxLayout()
        self.logs_output = QtWidgets.QListWidget()
        self.logs_output.itemClicked.connect(self.on_log_item_clicked)
        main_logs_layout.addWidget(self.logs_output)
        self.logs_tab.setLayout(main_logs_layout)
        self.tabs.addTab(self.logs_tab, "Logs")

        # Populate quarantine items and logs on startup
        self.refresh_quarantine_list()
        self.load_logs()

    def create_tray_icon(self):
        """
        Set up a system tray (menu bar) icon so the app can keep running
        when the main window is closed.
        """
        # Use the same small icon from the toolbar, or pick any QIcon you like:
        big_size = 64
        big_pixmap = QtGui.QPixmap(big_size, big_size)
        big_pixmap.fill(QtCore.Qt.transparent)

        painter = QtGui.QPainter(big_pixmap)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.setRenderHint(QtGui.QPainter.HighQualityAntialiasing)
        pen = QtGui.QPen(QtGui.QColor("#ffd700"))
        pen.setWidth(4)
        painter.setPen(pen)
        painter.setBrush(QtCore.Qt.NoBrush)
        painter.drawEllipse(QtCore.QPointF(big_size / 2, big_size / 2), 28, 28)
        shaft_top = QtCore.QPointF(big_size / 2, big_size * 0.15)
        shaft_bottom = QtCore.QPointF(big_size / 2, big_size * 0.4)
        painter.drawLine(shaft_top, shaft_bottom)
        arrow_head = [
            QtCore.QPointF(big_size / 2 - 10, big_size * 0.38),
            QtCore.QPointF(big_size / 2 + 10, big_size * 0.38),
            QtCore.QPointF(big_size / 2, big_size * 0.55)
        ]
        painter.setBrush(QtGui.QBrush(QtGui.QColor("#ffd700")))
        painter.drawPolygon(QtGui.QPolygonF(arrow_head))
        painter.setBrush(QtCore.Qt.NoBrush)
        painter.setPen(pen)
        painter.drawLine(
            QtCore.QPointF(big_size / 2 - 14, big_size * 0.7),
            QtCore.QPointF(big_size / 2 + 14, big_size * 0.7)
        )
        painter.end()

        small_pixmap = big_pixmap.scaled(
            24, 24,
            QtCore.Qt.KeepAspectRatio,
            QtCore.Qt.SmoothTransformation
        )
        tray_icon = QtGui.QIcon(small_pixmap)

        self.tray = QtWidgets.QSystemTrayIcon(self)
        self.tray.setIcon(tray_icon)
        self.tray.setToolTip("ByteMe is running in the background")
        menu = QtWidgets.QMenu()

        show_action = menu.addAction("Show ByteMe")
        show_action.triggered.connect(self.show_window)

        quit_action = menu.addAction("Quit ByteMe")
        quit_action.triggered.connect(QtWidgets.QApplication.instance().quit)

        self.tray.setContextMenu(menu)
        self.tray.show()

    def show_window(self):
        """
        Restore the main window if it was hidden.
        """
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event):
        """
        Override the default close to hide the window instead of quitting.
        """
        event.ignore()
        self.hide()
        send_notification(
            "ByteMe",
            "ByteMe is still running in the menu bar. Use the icon to restore or quit."
        )

    def on_check_updates(self):
        """
        Check GitHub Releases for a newer version, prompt & install if desired.
        """
        api_url = "https://api.github.com/repos/ThinkLikeMe/ByteMe/releases/latest"
        try:
            resp = requests.get(api_url, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            send_notification("Update Check Failed", str(e))
            return

        data = resp.json()
        latest_tag = data.get("tag_name", "")
        latest_ver = latest_tag.lstrip("v")
        if version.parse(latest_ver) > version.parse(APP_VERSION):
            # pick the first .tar.gz asset
            asset = next(
                (a for a in data.get("assets", []) if a["name"].endswith(".tar.gz")),
                None
            )
            if not asset:
                send_notification("Update Error", "No .tar.gz asset in latest release.")
                return

            dl_url = asset["browser_download_url"]
            reply = QtWidgets.QMessageBox.question(
                self,
                "Update Available",
                f"A new version ({latest_ver}) is available.\n\nDownload & install now?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            if reply == QtWidgets.QMessageBox.Yes:
                self.download_and_install_new_app_bundle(dl_url)
        else:
            QtWidgets.QMessageBox.information(
                self,
                "Up To Date",
                f"You are already on the latest version ({APP_VERSION})."
            )

    def download_and_install_new_app_bundle(self, download_url):
        """
        Download the .tar.gz, extract to a temp dir, then hand off to AppleScript
        that will quit, replace the old .app, and relaunch ByteMe.
        """
        try:
            # 1) Download archive
            tmpdir = tempfile.mkdtemp()
            tarball = os.path.join(tmpdir, "ByteMe.tar.gz")
            with requests.get(download_url, stream=True) as r:
                r.raise_for_status()
                with open(tarball, "wb") as f:
                    shutil.copyfileobj(r.raw, f)

            # 2) Extract it
            with tarfile.open(tarball, "r:gz") as tar:
                tar.extractall(path=tmpdir)

            # 3) Locate the .app bundle
            new_app = next(
                os.path.join(root, d)
                for root, dirs, _ in os.walk(tmpdir)
                for d in dirs
                if d.endswith(".app")
            )

            # 4) Build the AppleScript helper
            old_app = os.path.expanduser("~/Applications/ByteMe.app")
            q = shlex.quote
            script = f'''
                tell application "ByteMe" to quit
                delay 1
                do shell script "rm -rf {q(old_app)} && mv {q(new_app)} {q(old_app)}"
                delay 1
                do shell script "open {q(old_app)}"
            '''

            # 5) Launch it detached
            subprocess.Popen(["osascript", "-e", script])

            # 6) Quit now so the helper can swap bundles
            QtWidgets.QApplication.quit()

        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self,
                "Update Failed",
                f"Something went wrong during the update:\n{e}"
            )

    def add_log(self, headline: str, detail: str):
        """
        Append a log entry to the main logs:
        - headline shown in QListWidget
        - detail stored in UserRole for clicking.
        Also append to on-disk log file.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        display_text = f"[{timestamp}] {headline}"
        item = QtWidgets.QListWidgetItem(display_text)
        item.setData(QtCore.Qt.UserRole, detail)
        self.logs_output.addItem(item)

        try:
            with open(LOG_FILE_PATH, "a") as f:
                escaped_detail = detail.replace("\n", "\\n")
                f.write(f"[{timestamp}] {headline} → {escaped_detail}\n")
        except Exception:
            pass

    def load_logs(self):
        """
        Read each line from the on-disk log file and populate main logs.
        """
        try:
            with open(LOG_FILE_PATH, "r") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    if " → " in line:
                        prefix, raw_detail = line.split(" → ", 1)
                        detail = raw_detail.replace("\\n", "\n")
                    else:
                        prefix = line
                        detail = ""
                    item = QtWidgets.QListWidgetItem(prefix)
                    item.setData(QtCore.Qt.UserRole, detail)
                    self.logs_output.addItem(item)
        except Exception:
            pass

    def on_log_item_clicked(self, item: QtWidgets.QListWidgetItem):
        """
        Show a dialog with the log detail when clicked.
        """
        detail = item.data(QtCore.Qt.UserRole) or "(no additional detail)"
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Log Detail")
        dlg.setMinimumSize(600, 400)
        layout = QtWidgets.QVBoxLayout(dlg)
        text = QtWidgets.QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(detail)
        layout.addWidget(text)
        dlg.exec_()

    def add_vulnerability_tab(self):
        """
        Create a "Vulnerability" tab with subtabs:
        1. Search CVEs
        2. Scan System
        """
        from PyQt5.QtWidgets import (
            QVBoxLayout, QWidget, QPushButton, QTextEdit, QLineEdit,
            QLabel, QTabWidget
        )

        self.vuln_tab = QWidget()
        self.vuln_tabs = QTabWidget()

        # CVE Search
        self.vuln_search_tab = QWidget()
        search_layout = QVBoxLayout()
        self.vuln_input = QLineEdit()
        self.vuln_input.setPlaceholderText("Enter app name, CVE ID, URL, hash, or domain…")
        self.vuln_search_button = QPushButton("Search Vulnerabilities")
        self.vuln_search_button.clicked.connect(self.search_vulnerabilities)
        self.vuln_results = QTextEdit()
        self.vuln_results.setReadOnly(True)
        search_layout.addWidget(QLabel("Search CVEs"))
        search_layout.addWidget(self.vuln_input)
        search_layout.addWidget(self.vuln_search_button)
        search_layout.addWidget(self.vuln_results)
        self.vuln_search_tab.setLayout(search_layout)
        self.vuln_tabs.addTab(self.vuln_search_tab, "Search CVEs")

        # System Scan
        self.vuln_system_tab = QWidget()
        system_layout = QVBoxLayout()
        self.vuln_scan_button = QPushButton("Scan Installed Applications")
        self.vuln_scan_button.clicked.connect(self.run_vulnerability_scan)
        self.vuln_output = QTextEdit()
        self.vuln_output.setReadOnly(True)
        system_layout.addWidget(QLabel("System Vulnerability Scan"))
        system_layout.addWidget(self.vuln_scan_button)
        system_layout.addWidget(self.vuln_output)
        self.vuln_system_tab.setLayout(system_layout)
        self.vuln_tabs.addTab(self.vuln_system_tab, "Scan System")

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.vuln_tabs)
        self.vuln_tab.setLayout(main_layout)
        self.tabs.addTab(self.vuln_tab, "Vulnerability")

    def browse_folder(self):
        """
        Ask user to choose file or folder to scan, then store in self.scan_folder.
        """
        msg = QtWidgets.QMessageBox(self)
        msg.setWindowTitle("Scan Target")
        msg.setText("Do you want to scan a single file, or an entire folder?")
        file_btn = msg.addButton("File", QtWidgets.QMessageBox.AcceptRole)
        folder_btn = msg.addButton("Folder", QtWidgets.QMessageBox.AcceptRole)
        cancel_btn = msg.addButton("Cancel", QtWidgets.QMessageBox.RejectRole)
        msg.exec_()

        chosen = msg.clickedButton()
        if chosen == cancel_btn:
            return

        if chosen == file_btn:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Select File to Scan", self.scan_folder
            )
        else:
            path = QtWidgets.QFileDialog.getExistingDirectory(
                self, "Select Folder to Scan", self.scan_folder
            )

        if path:
            self.folder_input.setText(path)
            self.scan_folder = path

    def recursive_scan(self):
        """
        Scan a single file or directory recursively for malicious files.
        If malicious, quarantine immediately.
        """
        target = self.folder_input.text().strip()
        self.scan_result.clear()

        if not target:
            self.scan_result.append("No file or folder selected.")
            detail = self.scan_result.toPlainText()
            self.add_log("File Scan aborted (no target)", detail)
            return

        if os.path.isfile(target):
            self.scan_result.append(f"Scanning file: {target}…")
            vt_result = self.scan_file(target)
            self.scan_result.append(vt_result)
            if "⚠️ Malicious detections" in vt_result or "⚠️ Malicious (community pulses found)" in vt_result:
                self.quarantine_file(target, vt_result)
            detail = self.scan_result.toPlainText()
            self.add_log(f"File Scan completed on file: {target}", detail)
            return

        if os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                for name in files:
                    full_path = os.path.join(root, name)
                    if not os.path.isfile(full_path):
                        continue
                    self.scan_result.append(f"Scanning {full_path}…")
                    vt_result = self.scan_file(full_path)
                    self.scan_result.append(vt_result)
                    if "⚠️ Malicious detections" in vt_result or "⚠️ Malicious (community pulses found)" in vt_result:
                        self.quarantine_file(full_path, vt_result)
            detail = self.scan_result.toPlainText()
            self.add_log(f"File Scan completed on folder: {target}", detail)
            return

        self.scan_result.append("Invalid path. Please select a file or folder.")
        detail = self.scan_result.toPlainText()
        self.add_log(f"File Scan failed (invalid path): {target}", detail)

    def scan_file(self, file_path):
        """
        1) Compute SHA-256
        2) Query VirusTotal
        3) Query AlienVault OTX
        Returns combined result string.
        """
        if not self.api_key:
            return "No VirusTotal API key set."

        file_hash = self.get_sha256(file_path)
        if not file_hash:
            return "Error computing file hash."

        vt_result = self._vt_file_lookup(file_hash)
        otx_result = self._otx_file_lookup(file_hash)
        return f"{vt_result}\n{otx_result}"

    def _vt_file_lookup(self, file_hash):
        """
        Return a string summary of VirusTotal response for a file‐hash lookup.
        """
        headers = {"x-apikey": self.api_key}
        lookup_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(lookup_url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            if malicious > 0:
                return f"VT: ⚠️ Malicious detections: {malicious}"
            else:
                return "VT: ✅ No malicious detections found."
        elif response.status_code == 404:
            return "VT: ✅ No record on VirusTotal (not seen)"
        else:
            return f"VT: Error: HTTP {response.status_code}"

    def _otx_file_lookup(self, file_hash):
        """
        Return a string summary of AlienVault OTX response for a file‐hash lookup.
        """
        if not self.otx_api_key:
            return "OTX: No OTX API key set."

        headers = {"X-OTX-API-KEY": self.otx_api_key}
        lookup_url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
        response = requests.get(lookup_url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("pulse_info", {})
            pulse_count = data.get("count", 0)
            if pulse_count > 0:
                return "OTX: ⚠️ Malicious (community pulses found)"
            else:
                return "OTX: ✅ No pulses found (not seen in community pulses)"
        elif response.status_code == 404:
            return "OTX: ⚪️ No record on OTX (HTTP 404)"
        else:
            return f"OTX: Error: HTTP {response.status_code}"

    def get_sha256(self, file_path):
        """
        Compute SHA-256 hash of a file in streaming fashion.
        """
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""

    def scan_hash(self):
        """
        Manually input a file‐hash, then query:
        VirusTotal and AlienVault OTX.
        """
        file_hash = self.hash_input.text().strip()
        if not file_hash:
            self.hash_result.setPlainText("Please enter a file hash.")
            detail = self.hash_result.toPlainText()
            self.add_log("Hash Lookup aborted (no hash entered)", detail)
            return

        if not self.api_key:
            self.hash_result.setPlainText("VT: No API key set.")
        else:
            vt_res = self._vt_file_lookup(file_hash)
            self.hash_result.setPlainText(vt_res)

        if not self.otx_api_key:
            self.hash_result.append("OTX: No OTX API key set.")
        else:
            otx_res = self._otx_file_lookup(file_hash)
            self.hash_result.append(otx_res)

        detail = self.hash_result.toPlainText()
        self.add_log(f"Hash Lookup for {file_hash}", detail)

    def scan_url(self):
        """
        Manually input a URL, then:
        VirusTotal POST & GET, and AlienVault OTX GET.
        """
        url = self.url_input.text().strip()
        if not url:
            self.url_result.setPlainText("Please enter a URL.")
            detail = self.url_result.toPlainText()
            self.add_log("URL Lookup aborted (no URL entered)", detail)
            return

        if not self.api_key:
            self.url_result.setPlainText("VT: No API key set.")
        else:
            self.url_result.setPlainText(f"VT: Scanning {url}…")
            vt_summary = self._vt_url_lookup(url)
            self.url_result.append(vt_summary)

        if not self.otx_api_key:
            self.url_result.append("OTX: No OTX API key set.")
        else:
            otx_summary = self._otx_url_lookup(url)
            self.url_result.append(otx_summary)

        detail = self.url_result.toPlainText()
        self.add_log(f"URL Lookup for {url}", detail)

    def _vt_url_lookup(self, url):
        """
        Perform VT URL analysis: POST → GET.
        """
        headers = {"x-apikey": self.api_key}
        analyze_url = "https://www.virustotal.com/api/v3/urls"
        data = {"url": url}
        post_resp = requests.post(analyze_url, headers=headers, data=data)
        if post_resp.status_code != 200:
            return f"VT: Error initiating URL scan: HTTP {post_resp.status_code}"

        url_id = post_resp.json().get("data", {}).get("id", "")
        lookup_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        get_resp = requests.get(lookup_url, headers=headers)
        if get_resp.status_code == 200:
            stats = get_resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return f"VT: ⚠️ Malicious detections for URL: {malicious}"
            else:
                return "VT: ✅ No malicious detections found for URL."
        elif get_resp.status_code == 404:
            return "VT: ⚪️ No record on VirusTotal (URL not found)."
        else:
            return f"VT: Error fetching URL report: HTTP {get_resp.status_code}"

    def _otx_url_lookup(self, url):
        """
        OTX URL lookup: URL-encoded GET.
        """
        headers = {"X-OTX-API-KEY": self.otx_api_key}
        from urllib.parse import quote_plus
        encoded_url = quote_plus(url)
        lookup_url = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general"
        response = requests.get(lookup_url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("pulse_info", {})
            pulse_count = data.get("count", 0)
            if pulse_count > 0:
                return f"OTX: ⚠️ {pulse_count} pulse(s) for this URL."
            else:
                return "OTX: ✅ No pulses found for URL."
        elif response.status_code == 404:
            return "OTX: ⚪️ No record on OTX (URL not found)."
        else:
            return f"OTX: Error: HTTP {response.status_code}"

    def scan_domain(self):
        """
        Manually input a domain, then:
        VirusTotal GET and AlienVault OTX GET.
        """
        domain = self.domain_input.text().strip()
        if not domain:
            self.domain_result.setPlainText("Please enter a domain.")
            detail = self.domain_result.toPlainText()
            self.add_log("Domain Lookup aborted (no domain entered)", detail)
            return

        if not self.api_key:
            self.domain_result.setPlainText("VT: No API key set.")
        else:
            vt_summary = self._vt_domain_lookup(domain)
            self.domain_result.setPlainText(vt_summary)

        if not self.otx_api_key:
            self.domain_result.append("OTX: No OTX API key set.")
        else:
            otx_summary = self._otx_domain_lookup(domain)
            self.domain_result.append(otx_summary)

        detail = self.domain_result.toPlainText()
        self.add_log(f"Domain Lookup for {domain}", detail)

    def _vt_domain_lookup(self, domain):
        """
        VirusTotal domain lookup.
        """
        headers = {"x-apikey": self.api_key}
        lookup_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(lookup_url, headers=headers)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return f"VT: ⚠️ Malicious detections: {malicious}"
            else:
                return "VT: ✅ No malicious detections found."
        elif response.status_code == 404:
            return "VT: ⚪️ No record on VirusTotal (domain not found)."
        else:
            return f"VT: Error: HTTP {response.status_code}"

    def _otx_domain_lookup(self, domain):
        """
        OTX domain lookup.
        """
        headers = {"X-OTX-API-KEY": self.otx_api_key}
        lookup_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        response = requests.get(lookup_url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("pulse_info", {})
            pulse_count = data.get("count", 0)
            if pulse_count > 0:
                return f"OTX: ⚠️ {pulse_count} pulse(s) for this domain."
            else:
                return "OTX: ✅ No pulses found for domain."
        elif response.status_code == 404:
            return "OTX: ⚪️ No record on OTX (domain not found)."
        else:
            return f"OTX: Error: HTTP {response.status_code}"

    def search_vulnerabilities(self):
        """
        Manual CVE lookup via NVD:
        GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<term>&resultsPerPage=30
        """
        keyword = self.vuln_input.text().strip()
        if not keyword:
            self.vuln_results.setPlainText("Please enter a search term.")
            detail = self.vuln_results.toPlainText()
            self.add_log("CVE Search aborted (no keyword entered)", detail)
            return

        self.vuln_results.setPlainText(f"Searching for: {keyword}…")
        scanner = VulnerabilityScanner()
        cves = scanner.fetch_cve_data(keyword)
        self.vuln_results.clear()

        for entry in cves:
            if not isinstance(entry, dict) or "cve" not in entry:
                self.vuln_results.append("⚠️ Skipped malformed CVE entry.")
                continue

            cve_id = entry["cve"]["id"]
            desc = entry["cve"]["descriptions"][0]["value"]
            severity = "Unknown"

            metrics = entry["cve"].get("metrics", {})
            if isinstance(metrics, dict):
                cvss_v31 = metrics.get("cvssMetricV31", [])
                cvss_v2 = metrics.get("cvssMetricV2", [])
                if isinstance(cvss_v31, list) and cvss_v31:
                    severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                elif isinstance(cvss_v2, list) and cvss_v2:
                    severity = cvss_v2[0].get("cvssData", {}).get("baseSeverity", "Unknown")

            severity_icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }.get(severity.upper(), "⚪️")

            self.vuln_results.append(f"{severity_icon} {cve_id} ({severity}):\n{desc}\n")

        detail = self.vuln_results.toPlainText()
        self.add_log(f"CVE Search for '{keyword}'", detail)

    def run_vulnerability_scan(self):
        """
        Enumerate:
          - macOS .app bundles
          - Homebrew packages
          - pip3 packages
        Query NVD for each. Fallback to OSV if no NVD hits.
        """
        import plistlib
        import subprocess

        self.vuln_output.clear()
        self.vuln_output.append("🔍 Scanning installed applications and libraries for CVEs…\n")
        all_items = []

        def get_installed_apps_with_versions():
            app_dirs = ["/Applications", os.path.expanduser("~/Applications")]
            apps = []
            for app_dir in app_dirs:
                if os.path.exists(app_dir):
                    for item in os.listdir(app_dir):
                        if item.endswith(".app"):
                            full_path = os.path.join(app_dir, item)
                            info_plist_path = os.path.join(full_path, "Contents", "Info.plist")
                            version = "Unknown"
                            if os.path.exists(info_plist_path):
                                try:
                                    with open(info_plist_path, "rb") as f:
                                        plist = plistlib.load(f)
                                        version = plist.get("CFBundleShortVersionString", "Unknown")
                                except Exception:
                                    apps.append((item.replace(".app", ""), "Error reading version"))
                                    continue
                            apps.append((item.replace(".app", ""), version))
            return apps

        def get_brew_packages():
            packages = []
            try:
                output = subprocess.check_output(["brew", "list", "--versions"], text=True)
                for line in output.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        packages.append((name, version))
            except FileNotFoundError:
                packages.append(("Homebrew", "Not Installed"))
            except Exception as e:
                packages.append(("Homebrew", f"Error: {e}"))
            return packages

        def get_pip_packages():
            packages = []
            try:
                output = subprocess.check_output(["pip3", "list", "--format=freeze"], text=True)
                for line in output.strip().splitlines():
                    if "==" in line:
                        name, version = line.split("==")
                        packages.append((name, version))
            except FileNotFoundError:
                packages.append(("pip3", "Not Installed"))
            except Exception as e:
                packages.append(("pip3", f"Error: {e}"))
            return packages

        try:
            scanner = VulnerabilityScanner()
            for name, version in get_installed_apps_with_versions():
                all_items.append((name, version, "macOS App"))
            for name, version in get_brew_packages():
                all_items.append((name, version, "Homebrew"))
            for name, version in get_pip_packages():
                all_items.append((name, version, "pip"))

            for name, version, source in all_items:
                self.vuln_output.append(f"📦 {name} ({version}) from {source}")
                nvd_results = scanner.fetch_cve_data(f"{name} {version}")
                valid_nvd = [entry for entry in nvd_results if isinstance(entry, dict) and "cve" in entry]
                if valid_nvd:
                    for entry in valid_nvd:
                        cve_id = entry["cve"]["id"]
                        desc = entry["cve"]["descriptions"][0]["value"]
                        severity = "Unknown"
                        metrics = entry["cve"].get("metrics", {})
                        if isinstance(metrics, dict):
                            cvss_v31 = metrics.get("cvssMetricV31", [])
                            cvss_v2 = metrics.get("cvssMetricV2", [])
                            if cvss_v31 and isinstance(cvss_v31, list):
                                severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                            elif cvss_v2 and isinstance(cvss_v2, list):
                                severity = cvss_v2[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                        icon = {
                            "CRITICAL": "🔴",
                            "HIGH":     "🟠",
                            "MEDIUM":   "🟡",
                            "LOW":      "🟢"
                        }.get(severity.upper(), "⚪️")
                        self.vuln_output.append(f"{icon} {cve_id} ({severity}):\n{desc}\n")
                else:
                    self.vuln_output.append("⟳ No NVD results, trying OSV…")
                    osv_vulns = query_osv(name, version)
                    if not osv_vulns:
                        self.vuln_output.append("✅ No vulnerabilities found in NVD or OSV.\n")
                    else:
                        for vuln in osv_vulns:
                            cve_id = vuln.get("id", "Unknown")
                            summary = vuln.get("summary", "")
                            self.vuln_output.append(f"🟡 {cve_id} (OSV): {summary}\n")
        except Exception as e:
            self.vuln_output.append("❌ Unexpected error during scan:")
            self.vuln_output.append(str(e))

        detail = self.vuln_output.toPlainText()
        self.add_log("System Vulnerability Scan completed", detail)

    def on_save_settings(self):
        """
        Called when “Save Settings” is clicked. Update keys & interval, restart timer.
        """
        self.api_key = self.api_key_input.text().strip()
        self.otx_api_key = self.otx_api_key_input.text().strip()
        self.scan_interval_minutes = self.interval_input.value()

        if hasattr(self, "timer"):
            self.timer.stop()
            del self.timer

        if self.scan_interval_minutes > 0:
            self.timer = QtCore.QTimer(self)
            self.timer.timeout.connect(self.run_vulnerability_scan)
            self.timer.start(self.scan_interval_minutes * 60 * 1000)

        self.save_settings()
        QtWidgets.QMessageBox.information(self, "Settings Saved", "Settings have been saved.")

    def start_drive_monitor(self):
        """
        Set up a Watchdog observer on the Downloads folder,
        so only new files there get scanned.
        """
        downloads_path = os.path.expanduser("~/Downloads")
        self.drive_handler = FileChangeHandler(self.on_new_file)
        self.drive_observer = Observer()
        self.drive_observer.schedule(self.drive_handler, downloads_path, recursive=True)
        self.drive_observer.start()

    def on_new_file(self, file_path):
        """
        Callback for newly created files on the monitored drive.
        Scans the file and quarantines if malicious.
        """
        QtCore.QMetaObject.invokeMethod(
            self, "_notify_and_quarantine", QtCore.Qt.QueuedConnection,
            QtCore.Q_ARG(str, file_path)
        )

    @QtCore.pyqtSlot(str)
    def _notify_and_quarantine(self, file_path):
        """
        Performs scan, quarantines if malicious (anywhere on drive),
        and notifies via system notification instead of dialog.
        """
        if not os.path.isfile(file_path):
            return

        downloads_path = os.path.expanduser("~/Downloads")
        normalized_file = os.path.abspath(file_path)
        normalized_downloads = os.path.abspath(downloads_path)
        in_downloads = normalized_file.startswith(normalized_downloads + os.sep)

        vt_result = self.scan_file(file_path)
        malicious_detected = ("⚠️ Malicious detections" in vt_result or
                               "⚠️ Malicious (community pulses found)" in vt_result)

        if in_downloads:
            # Always send a notification for new files in Downloads
            if malicious_detected:
                send_notification(
                    "Malicious File Detected",
                    f"The file:\n{file_path}\nhas been flagged as malicious.\nQuarantining now."
                )
                self.quarantine_file(file_path, vt_result)
            else:
                send_notification(
                    "File Safe",
                    f"The file:\n{file_path}\nappears to be safe.\n{vt_result}"
                )
        else:
            if malicious_detected:
                send_notification(
                    "Malicious File Detected",
                    f"The file:\n{file_path}\nhas been flagged as malicious.\nQuarantining now."
                )
                self.quarantine_file(file_path, vt_result)
            # Otherwise: no notification for safe files outside Downloads

    def quarantine_file(self, file_path, vt_detail):
        """
        Move the malicious file into quarantine folder, record metadata, update UI.
        """
        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            quarantined_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(QUARANTINE_FOLDER, quarantined_name)
            shutil.move(file_path, quarantine_path)

            metadata = {
                "original_path": file_path,
                "quarantine_path": quarantine_path,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.quarantine_list_data.append(metadata)
            self.save_quarantine_metadata()
            self.refresh_quarantine_list()

            # Add an entry to quarantine logs subtab, including the reason
            reason_clean = vt_detail.strip().replace("\n", " ")
            log_entry = f"[{metadata['timestamp']}] Quarantined: {file_path}  |  Reason: {reason_clean}"
            self.quarantine_log_list.addItem(log_entry)

            # Also log to main logs
            self.add_log(f"Quarantined file: {file_path}", vt_detail)
        except Exception as e:
            # If moving fails, still log error
            self.add_log("Quarantine Error", f"Failed to move {file_path} to quarantine: {e}")

    def refresh_quarantine_list(self):
        """
        Repopulate the QListWidget for currently quarantined items.
        """
        self.quarantine_list.clear()
        for entry in self.quarantine_list_data:
            display_text = f"{entry['quarantine_path']}  ←  {entry['original_path']}"
            item = QtWidgets.QListWidgetItem(display_text)
            item.setData(QtCore.Qt.UserRole, entry)
            self.quarantine_list.addItem(item)

    def allow_quarantined_item(self):
        """
        Move the selected quarantined file into the ~/Documents folder,
        preserving its original filename, then remove it from metadata and UI.
        """
        selected = self.quarantine_list.currentItem()
        if not selected:
            return
        entry = selected.data(QtCore.Qt.UserRole)
        quarantine_path = entry["quarantine_path"]

        try:
            # Ensure ~/Documents exists
            dest_dir = os.path.expanduser("~/Documents")
            os.makedirs(dest_dir, exist_ok=True)

            # Use the original filename (not the timestamped one)
            filename = os.path.basename(entry["original_path"])
            dest_path = os.path.join(dest_dir, filename)

            # Move the file out of quarantine into Documents
            shutil.move(quarantine_path, dest_path)

            # Remove entry from metadata and update UI
            self.quarantine_list_data.remove(entry)
            self.save_quarantine_metadata()
            self.refresh_quarantine_list()

            # Log the restoration in the quarantine‐logs tab
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] Allowed: {dest_path}"
            self.quarantine_log_list.addItem(log_entry)

            # Also log to the main application log
            self.add_log(f"Allowed quarantined file: {dest_path}", "")

        except Exception as e:
            QtWidgets.QMessageBox.warning(
                self,
                "Allow Error",
                f"Failed to move file to Documents:\n{e}"
            )

    def remove_quarantined_item(self):
        """
        Permanently delete the selected quarantined file,
        remove from metadata and UI.
        """
        selected = self.quarantine_list.currentItem()
        if not selected:
            return
        entry = selected.data(QtCore.Qt.UserRole)
        quarantine_path = entry["quarantine_path"]

        try:
            os.remove(quarantine_path)
            self.quarantine_list_data.remove(entry)
            self.save_quarantine_metadata()
            self.refresh_quarantine_list()
            # Log
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] Removed: {quarantine_path}"
            self.quarantine_log_list.addItem(log_entry)
            self.add_log(f"Removed quarantined file: {quarantine_path}", "")
        except Exception as e:
            QtWidgets.QMessageBox.warning(
                self, "Remove Error", f"Failed to delete {quarantine_path}:\n{e}"
            )

    def start_scheduled_scan(self):
        """
        Placeholder (called in __init__). Actual QTimer setup happens in on_save_settings.
        """
        pass


class VulnerabilityScanner:
    """
    Wrapper for NVD JSON API (v2.0). Keyword search:
    GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<term>&resultsPerPage=30
    """
    def __init__(self):
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_cve_data(self, keyword):
        params = {"keywordSearch": keyword, "resultsPerPage": 30}
        try:
            response = requests.get(self.api_url, params=params, timeout=10)
            if response.status_code == 200:
                return response.json().get("vulnerabilities", [])
            else:
                return [{"error": f"Failed to fetch CVEs: HTTP {response.status_code}"}]
        except Exception as e:
            return [{"error": str(e)}]


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    # Ensure the application stays running when window is closed:
    app.setQuitOnLastWindowClosed(False)
    window = ByteMeWindow()
    window.show()
    sys.exit(app.exec_())
