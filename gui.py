import sys
import threading
import subprocess
import re
import requests
import os
import time
import ctypes
import random
import platform
from datetime import datetime
from collections import defaultdict
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QTime, QUrl, pyqtSlot
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWebEngineWidgets import QWebEngineView
import pyqtgraph as pg
import psutil
import folium
from folium.plugins import HeatMap
# ===============================
# IP GEOLOCATION
# ===============================
class GeoLocator:
    def __init__(self):
        self.cache = {}
        
    def get_location(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return {'lat': 40.7128, 'lon': -74.0060, 'city': 'Local', 'country': 'Local'}
        
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
            data = response.json()
            if data['status'] == 'success':
                location = {'lat': data['lat'], 'lon': data['lon'], 
                           'city': data['city'], 'country': data['country']}
                self.cache[ip] = location
                return location
        except:
            pass
        
        return {'lat': random.uniform(-90, 90), 'lon': random.uniform(-180, 180),
                'city': 'Unknown', 'country': 'Unknown'}

# ===============================
# SOUND MANAGER
# ===============================
class SoundManager:
    def __init__(self):
        self.enabled = True
        self.last_alert = 0
        
        # Load user32.dll for MessageBeep
        self.user32 = ctypes.windll.user32
    
    def play_alert(self, threat_level='low', attack_rate=0):
        # Only for CRITICAL attacks
        if attack_rate <= 200:
            return
        
        if not self.enabled:
            return
        
        if time.time() - self.last_alert < 3:
            return
        
        self.last_alert = time.time()
        threading.Thread(target=self._beep, daemon=True).start()
    
    def _beep(self):
        """Use Windows MessageBeep"""
        try:
            # MB_ICONHAND = 0x00000010 (Critical sound)
            for _ in range(3):
                self.user32.MessageBeep(0x00000010)
                time.sleep(0.3)
        except:
            print('\a', end='', flush=True)
    
    def test(self):
        """Test the sound"""
        print("Testing critical alert...")
        self._beep()
# ===============================
# EARTH MAP WIDGET
# ===============================
class EarthMapWidget(QWebEngineView):
    def __init__(self):
        super().__init__()
        self.attack_locations = []
        self.setup_map()
        
    def setup_map(self):
        m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
        legend_html = '''
        <div style="position: fixed; bottom: 20px; right: 20px; z-index: 1000; 
                    background: rgba(0,0,0,0.8); padding: 10px; border-radius: 8px;
                    color: white; font-family: monospace; font-size: 11px;
                    border-left: 3px solid #ff4444;">
            <b>🔴 LIVE ATTACK MAP</b><br>
            Red markers = Attack sources
        </div>
        '''
        m.get_root().html.add_child(folium.Element(legend_html))
        map_file = 'attack_map.html'
        m.save(map_file)
        self.load(QUrl.fromLocalFile(os.path.abspath(map_file)))
        
    def add_attack(self, lat, lon, ip, city, country, rate, attack_num):
        self.attack_locations.insert(0, (lat, lon, ip, city, country, rate, attack_num))
        m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
        
        for loc in self.attack_locations[:30]:
            lat, lon, ip, city, country, rate, num = loc
            popup = f"""
            <div style="font-family: monospace;">
                <b>🚨 ATTACK #{num}</b><br>
                IP: {ip}<br>
                Location: {city}, {country}<br>
                Rate: {rate:.0f} pps
            </div>
            """
            folium.Marker([lat, lon], popup=popup, 
                         icon=folium.Icon(color='red', icon='exclamation-triangle', prefix='fa')).add_to(m)
        
        map_file = 'attack_map.html'
        m.save(map_file)
        self.load(QUrl.fromLocalFile(os.path.abspath(map_file)))

# ===============================
# REAL-TIME CHART
# ===============================
class RealTimeChart(pg.PlotWidget):
    def __init__(self):
        super().__init__()
        self.setBackground('#1a1f3a')
        self.setLabel('left', 'Packets/sec')
        self.setLabel('bottom', 'Time (sec)')
        self.showGrid(x=True, y=True, alpha=0.3)
        self.setYRange(0, 500)
        self.setXRange(0, 60)
        self.plot_curve = self.plot(pen=pg.mkPen(color='#64ffda', width=2))
        self.data_line = [0] * 60
        
    def update_data(self, rate):
        self.data_line.append(rate)
        if len(self.data_line) > 60:
            self.data_line.pop(0)
        self.plot_curve.setData(self.data_line)
        if rate > 100:
            self.plot_curve.setPen(pg.mkPen(color='#ff4444', width=2))
        else:
            self.plot_curve.setPen(pg.mkPen(color='#64ffda', width=2))

# ===============================
# IP TABLE WIDGET
# ===============================
class IPTableWidget(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(["IP Address", "Country", "Packets", "Status"])
        self.setStyleSheet("""
            QTableWidget {
                background: #0a0e27;
                color: #c0c8e0;
                gridline-color: #1a2a3a;
                font-size: 12px;
            }
            QHeaderView::section {
                background: #1a1f3a;
                color: #64ffda;
                padding: 8px;
                font-weight: bold;
            }
        """)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.horizontalHeader().setStretchLastSection(True)

# ===============================
# MAIN DASHBOARD
# ===============================
class CyberShieldDashboard(QMainWindow):
    log_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(int, float, int)
    attack_signal = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberShield X - DDoS Protection System")
        self.setGeometry(100, 100, 1400, 800)
        self.setMinimumSize(1200, 700)
        
        # Set dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0e27;
            }
            QLabel {
                color: #c0c8e0;
            }
        """)
        
        # Variables
        self.process = None
        self.attack_count = 0
        self.current_rate = 0
        self.monitoring = False
        self.peak_rate = 0
        self.total_packets = 0
        self.ip_data = defaultdict(lambda: {'packets': 0, 'country': 'Unknown'})
        
        # Initialize managers
        self.sound_manager = SoundManager()
        self.geo_locator = GeoLocator()
        
        # Setup UI
        self.setup_ui()
        
        # Connect signals
        self.log_signal.connect(self.add_log)
        self.stats_signal.connect(self.update_stats)
        self.attack_signal.connect(self.on_attack_detected)
        
        # Timers
        self.sys_timer = QTimer()
        self.sys_timer.timeout.connect(self.update_system_stats)
        self.sys_timer.start(2000)
        
        self.chart_timer = QTimer()
        self.chart_timer.timeout.connect(self.update_chart)
        self.chart_timer.start(1000)
        
        # Initial log
        self.add_log("=" * 50)
        self.add_log("CyberShield X DDoS Protection System Ready")
        self.add_log("=" * 50)
        self.add_log("Click START MONITORING to begin")
        
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # ========== LEFT PANEL (Stats & Controls) ==========
        left_panel = QFrame()
        left_panel.setFixedWidth(400)
        left_panel.setStyleSheet("background-color: #0f1428; border-radius: 15px;")
        left_layout = QVBoxLayout()
        left_layout.setSpacing(15)
        left_layout.setContentsMargins(20, 20, 20, 20)
        
        # Logo
        logo = QLabel("⚡ CYBERSHIELD X")
        logo.setStyleSheet("font-size: 24px; font-weight: bold; color: #64ffda;")
        logo.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(logo)
        
        subtitle = QLabel("Enterprise DDoS Protection")
        subtitle.setStyleSheet("font-size: 11px; color: #8892b0;")
        subtitle.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(subtitle)
        
        # Status Indicator
        status_frame = QFrame()
        status_frame.setStyleSheet("background-color: #1a1f3a; border-radius: 15px;")
        status_layout = QVBoxLayout()
        
        self.status_indicator = QLabel("🟢")
        self.status_indicator.setStyleSheet("font-size: 48px;")
        self.status_indicator.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.status_indicator)
        
        self.status_text = QLabel("SYSTEM SECURE")
        self.status_text.setStyleSheet("font-size: 16px; font-weight: bold; color: #00ff88;")
        self.status_text.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.status_text)
        
        self.threat_level = QLabel("THREAT: LOW")
        self.threat_level.setStyleSheet("font-size: 11px; color: #00ff88;")
        self.threat_level.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.threat_level)
        
        status_frame.setLayout(status_layout)
        left_layout.addWidget(status_frame)
        
        # Stats Cards - Row 1
        stats_layout1 = QHBoxLayout()
        self.packet_card = self.create_card("PACKETS", "0")
        self.rate_card = self.create_card("CURRENT RATE", "0 pps")
        stats_layout1.addWidget(self.packet_card)
        stats_layout1.addWidget(self.rate_card)
        left_layout.addLayout(stats_layout1)
        
        # Stats Cards - Row 2
        stats_layout2 = QHBoxLayout()
        self.peak_card = self.create_card("PEAK RATE", "0 pps")
        self.attack_card = self.create_card("ATTACKS", "0")
        stats_layout2.addWidget(self.peak_card)
        stats_layout2.addWidget(self.attack_card)
        left_layout.addLayout(stats_layout2)
        
        # Live Chart
        chart_label = QLabel("📊 LIVE TRAFFIC")
        chart_label.setStyleSheet("font-size: 12px; font-weight: bold; color: #64ffda; margin-top: 10px;")
        left_layout.addWidget(chart_label)
        
        self.chart = RealTimeChart()
        self.chart.setFixedHeight(180)
        left_layout.addWidget(self.chart)
        
        # Buttons
        self.start_btn = QPushButton("▶ START MONITORING")
        self.start_btn.setStyleSheet("background-color: #00cc88; color: white; padding: 12px; border-radius: 10px; font-weight: bold; font-size: 13px;")
        self.start_btn.clicked.connect(self.start_monitoring)
        left_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹ STOP MONITORING")
        self.stop_btn.setStyleSheet("background-color: #ff4444; color: white; padding: 12px; border-radius: 10px; font-weight: bold; font-size: 13px;")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        left_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("🗑 CLEAR ALERTS")
        self.clear_btn.setStyleSheet("background-color: #ff8844; color: white; padding: 12px; border-radius: 10px; font-weight: bold; font-size: 13px;")
        self.clear_btn.clicked.connect(self.clear_alerts)
        left_layout.addWidget(self.clear_btn)
        
        # System Info
        sys_frame = QFrame()
        sys_frame.setStyleSheet("background-color: #1a1f3a; border-radius: 10px; padding: 10px;")
        sys_layout = QVBoxLayout()
        sys_layout.addWidget(QLabel("💻 SYSTEM"))
        
        self.cpu_label = QLabel("CPU: --%")
        self.mem_label = QLabel("RAM: --%")
        self.net_label = QLabel("NET: -- KB/s")
        
        for label in [self.cpu_label, self.mem_label, self.net_label]:
            label.setStyleSheet("color: #c0c8e0; font-size: 11px;")
            sys_layout.addWidget(label)
        
        sys_frame.setLayout(sys_layout)
        left_layout.addWidget(sys_frame)
        
        # Sound Toggle
        sound_layout = QHBoxLayout()
        self.sound_toggle = QCheckBox("🔊 SOUND ALERTS")
        self.sound_toggle.setChecked(True)
        self.sound_toggle.setStyleSheet("color: #c0c8e0; font-size: 11px;")
        self.sound_toggle.toggled.connect(lambda: setattr(self.sound_manager, 'enabled', self.sound_toggle.isChecked()))
        sound_layout.addWidget(self.sound_toggle)
        sound_layout.addStretch()
        left_layout.addLayout(sound_layout)
        
        left_layout.addStretch()
        left_panel.setLayout(left_layout)
        main_layout.addWidget(left_panel)
        
        # ========== RIGHT PANEL (Tabs) ==========
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                background-color: #0a0e27;
                border-radius: 10px;
                border: 1px solid #1a2a3a;
            }
            QTabBar::tab {
                background-color: #1a1f3a;
                color: #8892b0;
                padding: 10px 25px;
                margin: 3px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 12px;
            }
            QTabBar::tab:selected {
                background-color: #646cff;
                color: white;
            }
        """)
        
        # Tab 1: Attack Map
        map_tab = QWidget()
        map_layout = QVBoxLayout()
        map_title = QLabel("🌍 GLOBAL ATTACK MAP")
        map_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #64ffda; padding: 5px;")
        map_layout.addWidget(map_title)
        self.earth_map = EarthMapWidget()
        map_layout.addWidget(self.earth_map)
        map_tab.setLayout(map_layout)
        self.tab_widget.addTab(map_tab, "🗺️ MAP")
        
        # Tab 2: IP Tracking
        ip_tab = QWidget()
        ip_layout = QVBoxLayout()
        ip_title = QLabel("🌐 IP TRACKING")
        ip_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #64ffda; padding: 5px;")
        ip_layout.addWidget(ip_title)
        
        self.ip_search = QLineEdit()
        self.ip_search.setPlaceholderText("🔍 Search IP...")
        self.ip_search.setStyleSheet("background-color: #1a1f3a; color: #c0c8e0; border: 1px solid #2a2f4a; border-radius: 8px; padding: 8px; margin-bottom: 10px;")
        self.ip_search.textChanged.connect(self.search_ip)
        ip_layout.addWidget(self.ip_search)
        
        self.ip_table = IPTableWidget()
        ip_layout.addWidget(self.ip_table)
        ip_tab.setLayout(ip_layout)
        self.tab_widget.addTab(ip_tab, "🌐 IPs")
        
        # Tab 3: Alerts
        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout()
        alerts_title = QLabel("🔔 SECURITY ALERTS")
        alerts_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #64ffda; padding: 5px;")
        alerts_layout.addWidget(alerts_title)
        
        self.alerts_list = QListWidget()
        self.alerts_list.setStyleSheet("background-color: #0a0e27; color: #c0c8e0; border: 1px solid #1a2a3a; border-radius: 8px; font-size: 11px;")
        alerts_layout.addWidget(self.alerts_list)
        alerts_tab.setLayout(alerts_layout)
        self.tab_widget.addTab(alerts_tab, "🔔 ALERTS")
        
        # Tab 4: Logs
        logs_tab = QWidget()
        logs_layout = QVBoxLayout()
        logs_title = QLabel("📋 SYSTEM LOGS")
        logs_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #64ffda; padding: 5px;")
        logs_layout.addWidget(logs_title)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background-color: #050814; color: #c0c8e0; border: 1px solid #1a2a3a; border-radius: 8px; font-family: monospace; font-size: 11px;")
        logs_layout.addWidget(self.log_text)
        
        export_btn = QPushButton("💾 EXPORT LOGS")
        export_btn.setStyleSheet("background-color: #1a1f3a; color: #64ffda; border-radius: 8px; padding: 8px;")
        export_btn.clicked.connect(self.export_logs)
        logs_layout.addWidget(export_btn)
        
        logs_tab.setLayout(logs_layout)
        self.tab_widget.addTab(logs_tab, "📋 LOGS")
        
        # Tab 5: Stats
        stats_tab = QWidget()
        stats_layout = QVBoxLayout()
        stats_title = QLabel("📊 STATISTICS")
        stats_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #64ffda; padding: 5px;")
        stats_layout.addWidget(stats_title)
        
        stats_grid = QGridLayout()
        stats_grid.setSpacing(10)
        
        self.total_attacks = self.create_stat_box("Total Attacks", "0")
        self.peak_attack_rate = self.create_stat_box("Peak Attack Rate", "0 pps")
        self.avg_rate = self.create_stat_box("Avg Attack Rate", "0 pps")
        
        stats_grid.addWidget(self.total_attacks, 0, 0)
        stats_grid.addWidget(self.peak_attack_rate, 0, 1)
        stats_grid.addWidget(self.avg_rate, 1, 0)
        
        stats_layout.addLayout(stats_grid)
        stats_layout.addStretch()
        stats_tab.setLayout(stats_layout)
        self.tab_widget.addTab(stats_tab, "📊 STATS")
        
        main_layout.addWidget(self.tab_widget, stretch=2)
        central.setLayout(main_layout)
    
    def create_card(self, title, value):
        card = QFrame()
        card.setStyleSheet("background-color: #1a1f3a; border-radius: 10px;")
        layout = QVBoxLayout()
        layout.setSpacing(5)
        layout.setContentsMargins(10, 8, 10, 8)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #8892b0; font-size: 10px;")
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setStyleSheet("color: #64ffda; font-size: 20px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)
        
        card.setLayout(layout)
        card.value_label = value_label
        return card
    
    def create_stat_box(self, title, value):
        box = QFrame()
        box.setStyleSheet("background-color: #1a1f3a; border-radius: 10px; padding: 10px;")
        layout = QVBoxLayout()
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #8892b0; font-size: 11px;")
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setStyleSheet("color: #64ffda; font-size: 18px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)
        
        box.setLayout(layout)
        box.value_label = value_label
        return box
    
    def search_ip(self):
        text = self.ip_search.text().lower()
        for row in range(self.ip_table.rowCount()):
            if self.ip_table.item(row, 0):
                match = text in self.ip_table.item(row, 0).text().lower()
                self.ip_table.setRowHidden(row, not match)
    
    def update_system_stats(self):
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent()
            net = psutil.net_io_counters()
            
            if hasattr(self, '_last_net'):
                rx_speed = (net.bytes_recv - self._last_net[0]) / 1024
                self.net_label.setText(f"NET: {rx_speed:.0f} KB/s")
            
            self.cpu_label.setText(f"CPU: {cpu:.0f}%")
            self.mem_label.setText(f"RAM: {mem:.0f}%")
            
            self._last_net = (net.bytes_recv, net.bytes_sent)
        except:
            pass
    
    def update_chart(self):
        self.chart.update_data(self.current_rate)
    
    def refresh_ip_table(self):
        self.ip_table.setRowCount(0)
        sorted_ips = sorted(self.ip_data.items(), key=lambda x: x[1]['packets'], reverse=True)[:50]
        
        for ip, data in sorted_ips:
            row = self.ip_table.rowCount()
            self.ip_table.insertRow(row)
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip))
            self.ip_table.setItem(row, 1, QTableWidgetItem(data.get('country', 'Unknown')))
            self.ip_table.setItem(row, 2, QTableWidgetItem(str(data.get('packets', 0))))
            status = "⚠️ ATTACKER" if data.get('packets', 0) > 100 else "🟢 NORMAL"
            self.ip_table.setItem(row, 3, QTableWidgetItem(status))
    
    @pyqtSlot(int, float, int)
    def update_stats(self, packets, rate, unique_ips):
        self.total_packets = packets
        self.current_rate = rate
        
        self.packet_card.value_label.setText(f"{packets}")
        self.rate_card.value_label.setText(f"{rate:.1f} pps")
        
        if rate > self.peak_rate:
            self.peak_rate = rate
            self.peak_card.value_label.setText(f"{rate:.1f} pps")
        
        # Update threat level
        if rate > 100:
            self.threat_level.setText("THREAT: CRITICAL")
            self.threat_level.setStyleSheet("font-size: 11px; color: #ff4444;")
        elif rate > 50:
            self.threat_level.setText("THREAT: HIGH")
            self.threat_level.setStyleSheet("font-size: 11px; color: #ff8844;")
        elif rate > 20:
            self.threat_level.setText("THREAT: MEDIUM")
            self.threat_level.setStyleSheet("font-size: 11px; color: #ffcc44;")
        else:
            self.threat_level.setText("THREAT: LOW")
            self.threat_level.setStyleSheet("font-size: 11px; color: #00ff88;")
    
    @pyqtSlot(dict)
    def on_attack_detected(self, attack_data):
        self.attack_count = attack_data['attack_num']
        self.attack_card.value_label.setText(str(self.attack_count))
        
        # Update stats tab
        self.total_attacks.value_label.setText(str(self.attack_count))
        self.peak_attack_rate.value_label.setText(f"{attack_data['rate']:.0f} pps")
        
        # Update IP tracking
        sample_ip = attack_data['sample_ip']
        self.ip_data[sample_ip]['packets'] += attack_data['packets']
        self.ip_data[sample_ip]['country'] = attack_data['country']
        self.refresh_ip_table()
        
        # Add to map
        location = self.geo_locator.get_location(sample_ip)
        self.earth_map.add_attack(location['lat'], location['lon'], sample_ip,
                                   attack_data['city'], attack_data['country'],
                                   attack_data['rate'], self.attack_count)
        
        # Add to alerts
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert_text = f"[{timestamp}] 🚨 DDoS ATTACK #{self.attack_count} | Rate: {attack_data['rate']:.0f} pps | Source: {sample_ip}"
        self.alerts_list.insertItem(0, alert_text)
        
        if self.alerts_list.count() > 100:
            self.alerts_list.takeItem(self.alerts_list.count() - 1)
        
        # Play sound
        self.sound_manager.play_alert()
        
        # Update status
        self.status_indicator.setText("🔴")
        self.status_text.setText("ATTACK DETECTED!")
        self.status_text.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff4444;")
        
        QTimer.singleShot(5000, self.reset_status)
    
    def reset_status(self):
        if self.current_rate < 50:
            self.status_indicator.setText("🟢")
            self.status_text.setText("SYSTEM SECURE")
            self.status_text.setStyleSheet("font-size: 16px; font-weight: bold; color: #00ff88;")
    
    def clear_alerts(self):
        self.alerts_list.clear()
        self.add_log("Alert history cleared")
    
    @pyqtSlot(str)
    def add_log(self, message):
        timestamp = QTime.currentTime().toString("hh:mm:ss")
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())
    
    def export_logs(self):
        filename = f"cybershield_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_text.toPlainText())
            self.add_log(f"Logs exported to {filename}")
        except Exception as e:
            self.add_log(f"Export failed: {e}")
    
    def start_monitoring(self):
        self.add_log("=" * 40)
        self.add_log("STARTING MONITORING...")
        self.add_log("=" * 40)
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.monitoring = True
        
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            detect_script = os.path.join(script_dir, "detect.py")
            
            if not os.path.exists(detect_script):
                self.add_log("[ERROR] detect.py not found!")
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                self.monitoring = False
                return
            
            self.process = subprocess.Popen(
                [sys.executable, "-u", detect_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )
            
            threading.Thread(target=self.read_output, daemon=True).start()
            self.add_log("[OK] Detection engine active")
            self.add_log("[INFO] Monitoring network traffic...")
            
        except Exception as e:
            self.add_log(f"[ERROR] {e}")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.monitoring = False
    
    def read_output(self):
        while self.monitoring and self.process:
            try:
                line = self.process.stdout.readline()
                if not line:
                    if self.process.poll() is not None:
                        break
                    continue
                
                line = line.strip()
                if line:
                    self.log_signal.emit(line)
                    
                    if "STATS|" in line:
                        parts = line.split("|")
                        if len(parts) >= 4:
                            packets = int(parts[1])
                            rate = float(parts[2])
                            ips = int(parts[3])
                            self.stats_signal.emit(packets, rate, ips)
                    
                    elif "ATTACK|" in line:
                        parts = line.split("|")
                        if len(parts) >= 6:
                            attack_data = {
                                'packets': int(parts[1]),
                                'rate': float(parts[2]),
                                'unique_ips': int(parts[3]),
                                'attack_num': int(parts[4]),
                                'reason': parts[5],
                                'sample_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                                'city': 'Attacker',
                                'country': 'Unknown'
                            }
                            self.attack_signal.emit(attack_data)
                            
            except Exception as e:
                print(f"Read error: {e}")
                break
    
    def stop_monitoring(self):
        self.add_log("=" * 40)
        self.add_log("STOPPING MONITORING...")
        self.add_log("=" * 40)
        
        self.monitoring = False
        
        if self.process:
            try:
                self.process.terminate()
                time.sleep(1)
                if self.process.poll() is None:
                    self.process.kill()
            except:
                pass
            self.process = None
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.add_log("[OK] Monitoring stopped")
    
    def closeEvent(self, event):
        self.stop_monitoring()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = CyberShieldDashboard()
    window.show()
    sys.exit(app.exec_())