#!/usr/bin/env python3
"""
Neo Scanner – 100% Real DOS VGA Font + CRT Hacker GUI
Font: Perfect DOS VGA 437 | Green Phosphor | Web Scan | Fully Applied Font
"""

import sys
import os
import threading
import nmap
import requests
import re
from urllib.parse import urlparse
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTableWidget, QTableWidgetItem, QTextEdit, QLineEdit,
    QPushButton, QHeaderView, QGraphicsOpacityEffect
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QFontDatabase, QPalette, QColor, QPainter, QPixmap


# --------------------------- SCAN WORKER ---------------------------
class ScanWorker(QThread):
    log_signal = pyqtSignal(str, str)
    update_matrix = pyqtSignal(dict)
    scan_finished = pyqtSignal()

    def __init__(self, url):
        super().__init__()
        self.url = url
        self.domain = self.extract_domain(url)

    def extract_domain(self, url):
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        return parsed.netloc.split(':')[0]

    def run(self):
        if not self.domain:
            self.log_signal.emit("INVALID URL", "ALERT")
            self.scan_finished.emit()
            return

        self.log_signal.emit(f"LOCK ON: {self.url}", "INFO")
        self.log_signal.emit(f"DOMAIN: {self.domain}", "INFO")

        try:
            import socket
            ip = socket.gethostbyname(self.domain)
            self.log_signal.emit(f"IP: {ip}", "INFO")
        except:
            self.log_signal.emit("DOMAIN NOT FOUND", "ALERT")
            self.scan_finished.emit()
            return

        ports_data = self.scan_web_ports(self.domain, ip)
        self.update_matrix.emit({self.domain: ports_data})
        self.scan_finished.emit()

    def scan_web_ports(self, domain, ip):
        nm = nmap.PortScanner()
        try:
            nm.scan(ip, '80,443,8080,8443', arguments='--open -Pn -T4 -n')
        except:
            pass

        web_info = {"ports": [], "title": "NO TITLE", "server": "UNKNOWN", "tech": [], "security": []}
        http_ports = []

        if ip in nm.all_hosts():
            for port in nm[ip].get('tcp', {}):
                if nm[ip]['tcp'][port]['state'] == 'open':
                    service = nm[ip]['tcp'][port].get('name', 'unknown')
                    version = f"{nm[ip]['tcp'][port].get('product', '')} {nm[ip]['tcp'][port].get('version', '')}".strip()
                    web_info["ports"].append({"port": port, "service": service, "version": version})
                    self.log_signal.emit(f"PORT {port} OPEN", "OPEN")
                    if 'http' in service:
                        http_ports.append(port)

        for port in http_ports:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{domain}:{port}"
            try:
                r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                title_match = re.search(r'<title>(.*?)</title>', r.text, re.I)
                title = (title_match.group(1)[:45] + "...") if title_match and len(
                    title_match.group(1)) > 45 else title_match.group(1) if title_match else "NO TITLE"
                if web_info["title"] == "NO TITLE":
                    web_info["title"] = title
                self.log_signal.emit(f"TITLE: \"{title}\"", "WEB")

                server = r.headers.get('Server', 'UNKNOWN')
                web_info["server"] = server
                self.log_signal.emit(f"SERVER: {server}", "INFO")

                tech = []
                if 'x-powered-by' in r.headers: tech.append(r.headers['x-powered-by'].split(',')[0])
                if 'wordpress' in r.text.lower(): tech.append("WordPress")
                if 'react' in r.text.lower(): tech.append("React")
                web_info["tech"].extend(tech)

                sec = {'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security'}
                missing = sec - set(r.headers.keys())
                for h in missing:
                    self.log_signal.emit(f"SEC: {h} MISSING", "ALERT")
                web_info["security"] = list(sec - missing)

            except Exception as e:
                self.log_signal.emit(f"HTTP ERROR", "ALERT")

        return web_info


# --------------------------- MAIN GUI ---------------------------
class NeoScannerDOS(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NEO SCANNER v9.9 - DOS MODE")
        self.setGeometry(100, 100, 1280, 800)
        self.results = {}
        self.worker = None

        # CRT Flicker
        self.crt_timer = QTimer()
        self.crt_timer.timeout.connect(self.crt_flicker)
        self.crt_timer.start(120)

        self.dos_font = None
        self.setup_ui()
        self.load_dos_font()
        self.apply_crt_style()
        self.apply_font_to_all()
        self.log("SYSTEM BOOT", "INFO")
        self.log("ENTER URL", "INFO")

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        self.header = QLabel(
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║                NEO SCANNER v9.9 - WEB RECON                  ║\n"
            "╚══════════════════════════════════════════════════════════════╝"
        )
        self.header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.header)

        # Matrix
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["DOMAIN", "PORTS", "TITLE", "SERVER", "SECURITY"])
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(QLabel("TARGET MATRIX"))
        layout.addWidget(self.table)

        # ASCII Map
        self.map_display = QTextEdit()
        self.map_display.setReadOnly(True)
        layout.addWidget(QLabel("NETWORK TOPOLOGY"))
        layout.addWidget(self.map_display)

        # Log
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(QLabel("SYSTEM LOG"))
        layout.addWidget(self.log_display)

        # Input
        control = QHBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("HTTPS://TARGET.COM")
        control.addWidget(self.input_field)

        self.start_btn = QPushButton("EXECUTE")
        self.start_btn.clicked.connect(self.start_scan)
        control.addWidget(self.start_btn)

        self.clear_btn = QPushButton("PURGE")
        self.clear_btn.clicked.connect(self.clear_all)
        control.addWidget(self.clear_btn)

        layout.addLayout(control)

        # CRT Overlay
        self.crt_overlay = QLabel(self)
        self.crt_overlay.setGeometry(0, 0, self.width(), self.height())
        self.crt_overlay.lower()

    def load_dos_font(self):
        """Load Perfect DOS VGA 437 font and store in self.dos_font."""
        font_path = "fonts/Perfect_DOS_VGA_437.ttf"
        if not os.path.exists(font_path):
            self.log("FONT MISSING: fonts/Perfect_DOS_VGA_437.ttf", "ALERT")
            self.log("DOWNLOAD FROM README", "INFO")
            self.dos_font = QFont("Courier New", 11)
            self.dos_font.setFixedPitch(True)
            return

        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id == -1:
            self.log("FONT LOAD FAILED", "ALERT")
            self.dos_font = QFont("Courier New", 11)
            self.dos_font.setFixedPitch(True)
            return

        font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
        self.dos_font = QFont(font_family, 11)
        self.dos_font.setStyleHint(QFont.StyleHint.Monospace)
        self.dos_font.setFixedPitch(True)
        self.log("DOS VGA FONT LOADED", "INFO")

    def apply_font_to_all(self):
        """Apply DOS font to every widget after setup."""
        if not self.dos_font:
            return

        widgets = [
            self.header, self.table, self.map_display, self.log_display,
            self.input_field, self.start_btn, self.clear_btn
        ]
        for widget in widgets:
            if widget:
                widget.setFont(self.dos_font)

        # Apply to table items and header
        header = self.table.horizontalHeader()
        if header:
            header.setFont(self.dos_font)

        # Apply to existing items
        for row in range(self.table.rowCount()):
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    item.setFont(self.dos_font)

        # Apply to log
        self.log_display.setFont(self.dos_font)

    def apply_crt_style(self):
        self.setStyleSheet(f"""
            * {{ 
                background-color: #000000; 
                color: #00ff00; 
                border: 1px solid #003300;
                font-family: '{self.dos_font.family() if self.dos_font else "Courier"}';
                font-size: 11pt;
            }}
            QLineEdit, QPushButton, QTextEdit, QTableWidget {{
                background-color: #000000;
                color: #00ff00;
                border: 1px solid #003300;
                padding: 4px;
            }}
            QPushButton {{ 
                font-weight: bold; 
                background-color: #001100; 
            }}
            QHeaderView::section {{ 
                background-color: #001100; 
                color: #00ff80; 
                font-weight: bold; 
                border: 1px solid #003300;
            }}
            QLabel {{ border: none; }}
        """)

        self.update_crt_scanlines()

    def update_crt_scanlines(self):
        pixmap = QPixmap(self.size())
        pixmap.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pixmap)
        painter.setPen(QColor(0, 40, 0, 25))
        for y in range(0, self.height(), 3):
            painter.drawLine(0, y, self.width(), y)
        painter.end()
        self.crt_overlay.setPixmap(pixmap)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.crt_overlay.setGeometry(0, 0, self.width(), self.height())
        self.update_crt_scanlines()

    def crt_flicker(self):
        opacity = 0.03 if (datetime.now().microsecond // 500000) % 2 else 0.06
        self.crt_overlay.setStyleSheet(f"background: rgba(0, 50, 0, {opacity});")

    def log(self, msg, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {"INFO": "#00ff00", "OPEN": "#00ff80", "WEB": "#ffff00", "ALERT": "#ff0000"}
        self.log_display.append(f'<span style="color:{colors.get(level, "#00ff00")}">[{timestamp}] {msg}</span>')
        self.log_display.ensureCursorVisible()

    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        url = self.input_field.text().strip()
        if not url:
            self.log("NO TARGET", "ALERT")
            return

        self.start_btn.setEnabled(False)
        self.worker = ScanWorker(url)
        self.worker.log_signal.connect(self.log)
        self.worker.update_matrix.connect(self.update_matrix)
        self.worker.scan_finished.connect(self.scan_finished)
        self.worker.start()

    def update_matrix(self, data):
        for domain, info in data.items():
            self.results[domain] = info
            row = self.table.rowCount()
            self.table.insertRow(row)
            ports = ", ".join(str(p['port']) for p in info['ports'])
            tech = " | ".join(info['tech']) if info['tech'] else "UNKNOWN"
            sec = len(info['security'])
            items = [
                QTableWidgetItem(domain),
                QTableWidgetItem(ports),
                QTableWidgetItem(info['title']),
                QTableWidgetItem(f"{info['server']} | {tech}"),
                QTableWidgetItem(f"{sec}/3 SEC")
            ]
            for col, item in enumerate(items):
                item.setFont(self.dos_font)
                self.table.setItem(row, col, item)
        self.update_ascii_map()

    def update_ascii_map(self):
        lines = [
            "        ┌──────────┐",
            "        │ INTERNET │",
            "        └──────────┘",
            "              │",
        ]
        for i, (domain, info) in enumerate(list(self.results.items())[:2]):
            tech = info['tech'][0] if info['tech'] else "WEB"
            lines.append(f"              │           ◆ [{domain}] → {tech}")
        while len(lines) < 8:
            lines.append("")
        lines.append("        ◆ = WEB SERVER    → = DATA FLOW")
        self.map_display.setPlainText("\n".join(lines))

    def scan_finished(self):
        self.start_btn.setEnabled(True)
        self.log("SCAN COMPLETE", "OPEN")

    def clear_all(self):
        self.results.clear()
        self.table.setRowCount(0)
        self.map_display.clear()
        self.log_display.clear()
        self.log("MEMORY PURGED", "INFO")


# --------------------------- RUN ---------------------------
if __name__ == "__main__":
    os.makedirs("fonts", exist_ok=True)

    app = QApplication(sys.argv)
    window = NeoScannerDOS()
    window.show()
    sys.exit(app.exec())