# src/gui/network_traffic_analyzer_tab.py

import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import threading
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.network_traffic_analyzer import (
    start_packet_capture,
    validate_filter,
    get_scapy_status,
    SCAPY_AVAILABLE
)

# PASSECURIST Theme Colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
BTN_HOVER = "#0ea5e9"
INPUT_BG = "#334155"
INPUT_VALID = "#22c55e"
INPUT_ERROR = "#ef4444"
SUCCESS_COLOR = "#22c55e"
ERROR_COLOR = "#ef4444"
WARNING_COLOR = "#f59e0b"
DETAIL_COLOR = "#94a3b8"

# Network Traffic Analyzer GUI
class NetworkTrafficAnalyzerTab:
    
    def __init__(self, parent):
        self.parent = parent
        self.parent.configure(bg=BG_COLOR)
        self.is_capturing = False
        self.capture_stopped = False
        self.packet_count = 0
        
        # Checks Scapy status
        self.scapy_installed, self.has_privileges, self.status_message = get_scapy_status()
        
        # Code for Scrollbar
        self.canvas = tk.Canvas(parent, bg=BG_COLOR, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(parent, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=BG_COLOR)
        
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.bind('<Configure>', self.on_canvas_configure)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Code for Mousewheel scrolling
        self.parent.bind_all("<MouseWheel>", self._on_mousewheel)
        
        self.setup_ui()
        
        self.scrollable_frame.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    
    def on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)
    
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.scrollable_frame, bg=BG_COLOR)
        header_frame.pack(fill="x", pady=(15, 10))
        
        tk.Label(header_frame, text="NETWORK TRAFFIC ANALYZER", 
                font=("Segoe UI", 24, "bold"),
                fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        
        tk.Label(header_frame, text="Capture and analyze real-time network packets with protocol filtering",
                font=("Segoe UI", 11), fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=(5, 0))
        
        # Center wrapper
        center_wrapper = tk.Frame(self.scrollable_frame, bg=BG_COLOR)
        center_wrapper.pack(fill="both", expand=True, padx=50, pady=10)
        
        # ONLY show Scapy installation warning if Scapy is not installed
        # Do NOT show warning for privilege issues (instructions panel handles that)
        if not self.scapy_installed:
            self.show_scapy_installation_warning(center_wrapper)
        
        # How to Run Instructions Panel - Always visible, updated status based on privileges
        self.show_instructions_panel(center_wrapper)
        
        # Configuration Panel
        config_frame = tk.Frame(center_wrapper, bg=CARD_COLOR, padx=30, pady=25)
        config_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(config_frame, text="CAPTURE CONFIGURATION", 
                font=("Segoe UI", 16, "bold"),
                fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w", pady=(0, 20))
        
        # Filter input
        filter_label_frame = tk.Frame(config_frame, bg=CARD_COLOR)
        filter_label_frame.pack(fill="x", pady=(0, 5))
        
        tk.Label(filter_label_frame, text="BPF Filter", 
                font=("Segoe UI", 11, "bold"),
                fg=TEXT_MAIN, bg=CARD_COLOR).pack(side="left")
        
        tk.Label(filter_label_frame, text=" (e.g., 'tcp and port 80', 'udp', 'icmp')", 
                font=("Segoe UI", 9),
                fg=DETAIL_COLOR, bg=CARD_COLOR).pack(side="left")
        
        self.filter_entry = tk.Entry(config_frame, font=("Consolas", 12),
                                     bg=INPUT_BG, fg=TEXT_MAIN,
                                     insertbackground="white", relief="flat")
        self.filter_entry.pack(fill="x", ipady=10, pady=(0, 5))
        self.filter_entry.insert(0, "")
        self.filter_entry.bind('<KeyRelease>', self.validate_filter_realtime)
        
        self.filter_status = tk.Label(config_frame, text="ℹ️ Leave empty to capture all packets", 
                                      font=("Segoe UI", 9),
                                      fg=DETAIL_COLOR, bg=CARD_COLOR, anchor="w")
        self.filter_status.pack(fill="x", pady=(0, 15))
        
        # Common filter examples
        # Includes all required protocol filters (TCP, UDP, ICMP)
        # and port filters (80/HTTP, 443/HTTPS, 53/DNS)
        # Additional ports like 22/SSH can be entered manually: "tcp and port 22"
        examples_frame = tk.Frame(config_frame, bg=CARD_COLOR)
        examples_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(examples_frame, text="Quick Filters:", 
                font=("Segoe UI", 10, "bold"),
                fg=TEXT_MAIN, bg=CARD_COLOR).pack(side="left", padx=(0, 10))
        
        quick_filters = [
            ("TCP", "tcp"),
            ("UDP", "udp"),
            ("ICMP", "icmp"),
            ("HTTP", "tcp and port 80"),
            ("HTTPS", "tcp and port 443"),
            ("DNS", "udp and port 53")
        ]
        
        for label, filter_text in quick_filters:
            btn = tk.Button(examples_frame, text=label,
                          command=lambda f=filter_text: self.set_filter(f),
                          bg=INPUT_BG, fg=TEXT_MAIN,
                          font=("Segoe UI", 9),
                          relief="flat", cursor="hand2",
                          padx=10, pady=5)
            btn.pack(side="left", padx=2)
        
        # Control buttons
        button_frame = tk.Frame(config_frame, bg=CARD_COLOR)
        button_frame.pack(fill="x")
        
        self.start_button = tk.Button(button_frame, text="START CAPTURE",
                                      command=self.start_capture,
                                      bg=ACCENT_COLOR, fg=BG_COLOR,
                                      font=("Segoe UI", 12, "bold"),
                                      relief="flat", cursor="hand2",
                                      state="normal" if (self.scapy_installed and self.has_privileges) else "disabled")
        self.start_button.pack(side="left", fill="x", expand=True, ipady=12, padx=(0, 5))
        
        self.stop_button = tk.Button(button_frame, text="STOP CAPTURE",
                                     command=self.stop_capture,
                                     bg=ERROR_COLOR, fg="white",
                                     font=("Segoe UI", 12, "bold"),
                                     relief="flat", cursor="hand2",
                                     state="disabled")
        self.stop_button.pack(side="left", fill="x", expand=True, ipady=12, padx=(5, 0))
        
        tk.Button(config_frame, text="CLEAR RESULTS",
                 command=self.clear_results,
                 bg="#475569", fg=TEXT_MAIN,
                 font=("Segoe UI", 10, "bold"),
                 relief="flat", cursor="hand2").pack(fill="x", ipady=10, pady=(10, 0))
        
        # Packet counter
        self.counter_label = tk.Label(config_frame, text="Packets Captured: 0", 
                                     font=("Segoe UI", 11, "bold"),
                                     fg=ACCENT_COLOR, bg=CARD_COLOR)
        self.counter_label.pack(pady=(15, 0))
        
        # Results section
        results_frame = tk.Frame(center_wrapper, bg=CARD_COLOR, padx=30, pady=25)
        results_frame.pack(fill="both", expand=True)
        
        tk.Label(results_frame, text="CAPTURED PACKETS", 
                font=("Segoe UI", 14, "bold"),
                fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w", pady=(0, 10))
        
        # Scrolled text for packet display
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            font=("Consolas", 9),
            bg="#0a0e1a",
            fg=TEXT_MAIN,
            insertbackground=ACCENT_COLOR,
            relief="flat",
            height=20,
            wrap=tk.WORD
        )
        self.results_text.pack(fill="both", expand=True)
        
        # Configure text tags for coloring
        self.results_text.tag_config("timestamp", foreground="#94a3b8")
        self.results_text.tag_config("tcp", foreground="#22c55e")
        self.results_text.tag_config("udp", foreground="#38bdf8")
        self.results_text.tag_config("icmp", foreground="#f59e0b")
        self.results_text.tag_config("other", foreground="#94a3b8")
        self.results_text.tag_config("ip", foreground="#e2e8f0")
        self.results_text.tag_config("port", foreground="#a78bfa")
    
    def show_scapy_installation_warning(self, parent):
        """Show warning ONLY if Scapy is not installed"""
        warning_frame = tk.Frame(parent, bg=ERROR_COLOR, padx=20, pady=15)
        warning_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(warning_frame, text="❌ Scapy Not Installed", 
                font=("Segoe UI", 13, "bold"),
                fg="white", bg=ERROR_COLOR).pack(anchor="w")
        
        tk.Label(warning_frame, 
                text="The Network Traffic Analyzer requires Scapy to function.\n\n"
                     "To install Scapy, open Command Prompt or Terminal and run:\n"
                     "    pip install scapy\n\n"
                     "After installation, restart this application.",
                font=("Consolas", 10),
                fg="white", bg=ERROR_COLOR, justify="left").pack(anchor="w", pady=(8, 0))
    
    def show_instructions_panel(self, parent):
        """Show instructions panel with dynamic status indicator"""
        instructions_frame = tk.Frame(parent, bg=CARD_COLOR, padx=25, pady=20)
        instructions_frame.pack(fill="x", pady=(0, 10))
        
        # Header with status indicator
        header_frame = tk.Frame(instructions_frame, bg=CARD_COLOR)
        header_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(header_frame, text="📋 ADMINISTRATOR PRIVILEGES", 
                font=("Segoe UI", 12, "bold"),
                fg=ACCENT_COLOR, bg=CARD_COLOR).pack(side="left")
        
        # Status indicator
        if self.scapy_installed and self.has_privileges:
            status_text = "✓ Ready"
            status_color = SUCCESS_COLOR
        elif self.scapy_installed and not self.has_privileges:
            status_text = "⚠ Required"
            status_color = WARNING_COLOR
        else:
            status_text = "⚠ Install Scapy First"
            status_color = ERROR_COLOR
        
        status_label = tk.Label(header_frame, text=status_text,
                               font=("Segoe UI", 10, "bold"),
                               fg=status_color, bg=CARD_COLOR)
        status_label.pack(side="right")
        
        # Creates three columns for different OS instructions
        columns_frame = tk.Frame(instructions_frame, bg=CARD_COLOR)
        columns_frame.pack(fill="x")
        
        # Windows Column
        windows_frame = tk.Frame(columns_frame, bg="#1a2332", padx=15, pady=12)
        windows_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        tk.Label(windows_frame, text="🪟 WINDOWS", 
                font=("Segoe UI", 10, "bold"),
                fg="#38bdf8", bg="#1a2332").pack(anchor="w", pady=(0, 8))
        
        windows_steps = (
            "1. Press Win + X\n"
            "2. Select 'Command Prompt (Admin)'\n"
            "   or 'PowerShell (Admin)'\n"
            "3. Navigate to project:\n"
            "   cd \"path\\to\\project\"\n"
            "4. Run:\n"
            "   python src/main.py"
        )
        tk.Label(windows_frame, text=windows_steps,
                font=("Consolas", 8),
                fg="#e2e8f0", bg="#1a2332",
                justify="left").pack(anchor="w")
        
        # Linux Column
        linux_frame = tk.Frame(columns_frame, bg="#1a2332", padx=15, pady=12)
        linux_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        tk.Label(linux_frame, text="🐧 LINUX", 
                font=("Segoe UI", 10, "bold"),
                fg="#38bdf8", bg="#1a2332").pack(anchor="w", pady=(0, 8))
        
        linux_steps = (
            "1. Open Terminal\n"
            "2. Navigate to project:\n"
            "   cd /path/to/project\n"
            "3. Run with sudo:\n"
            "   sudo python3 src/main.py\n"
            "4. Enter your password"
        )
        tk.Label(linux_frame, text=linux_steps,
                font=("Consolas", 8),
                fg="#e2e8f0", bg="#1a2332",
                justify="left").pack(anchor="w")
        
        # Mac Column
        mac_frame = tk.Frame(columns_frame, bg="#1a2332", padx=15, pady=12)
        mac_frame.pack(side="left", fill="both", expand=True, padx=(5, 0))
        
        tk.Label(mac_frame, text="🍎 MAC", 
                font=("Segoe UI", 10, "bold"),
                fg="#38bdf8", bg="#1a2332").pack(anchor="w", pady=(0, 8))
        
        mac_steps = (
            "1. Open Terminal\n"
            "2. Navigate to project:\n"
            "   cd /path/to/project\n"
            "3. Run with sudo:\n"
            "   sudo python3 src/main.py\n"
            "4. Enter your password"
        )
        tk.Label(mac_frame, text=mac_steps,
                font=("Consolas", 8),
                fg="#e2e8f0", bg="#1a2332",
                justify="left").pack(anchor="w")
        
        # Note at the bottom
        tk.Label(instructions_frame, 
                text="💡 Note: Packet capture requires elevated permissions to access network interfaces at the kernel level.",
                font=("Segoe UI", 9, "italic"),
                fg="#94a3b8", bg=CARD_COLOR,
                wraplength=900,
                justify="left").pack(anchor="w", pady=(10, 0))
    
    # Set filter from quick button
    def set_filter(self, filter_text):
        self.filter_entry.delete(0, tk.END)
        self.filter_entry.insert(0, filter_text)
        self.validate_filter_realtime()
    
    # Validate filter in real-time
    def validate_filter_realtime(self, event=None):
        filter_text = self.filter_entry.get().strip()
        
        if not filter_text:
            self.filter_status.config(text="ℹ️ Leave empty to capture all packets", fg=DETAIL_COLOR)
            return True
        
        is_valid, error_msg = validate_filter(filter_text)
        
        if is_valid:
            self.filter_status.config(text=f"✓ Valid filter: {filter_text}", fg=SUCCESS_COLOR)
            return True
        else:
            self.filter_status.config(text=f"⚠ {error_msg}", fg=ERROR_COLOR)
            return False
    
    # Clear results area
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.packet_count = 0
        self.counter_label.config(text="Packets Captured: 0")
    
    # Start capturing packets
    def start_capture(self):
        if self.is_capturing:
            messagebox.showwarning("Capturing", "Already capturing packets!")
            return
        
        if not self.scapy_installed:
            messagebox.showerror(
                "Scapy Not Installed", 
                "Scapy is required for packet capture.\n\n"
                "Install it using:\n"
                "pip install scapy\n\n"
                "Then restart the application."
            )
            return
        
        if not self.has_privileges:
            messagebox.showerror(
                "Privileges Required",
                "Administrator/root privileges are required for packet capture.\n\n"
                "Please restart the application with elevated privileges:\n\n"
                "Windows: Run as Administrator\n"
                "Linux/Mac: Use sudo"
            )
            return
        
        if not self.validate_filter_realtime():
            messagebox.showerror("Invalid Filter", "Please fix the filter before starting capture.")
            return
        
        filter_text = self.filter_entry.get().strip()
        
        self.clear_results()
        self.capture_stopped = False
        self.is_capturing = True
        
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.filter_entry.config(state='disabled')
        
        # Add start message
        self.results_text.insert(tk.END, f"{'='*100}\n", "other")
        self.results_text.insert(tk.END, "Capture started...\n", "other")
        if filter_text:
            self.results_text.insert(tk.END, f"Filter: {filter_text}\n", "other")
        else:
            self.results_text.insert(tk.END, "Filter: (all packets)\n", "other")
        self.results_text.insert(tk.END, f"{'='*100}\n\n", "other")
        self.results_text.see(tk.END)
        
        # Start capture in separate thread
        threading.Thread(target=self.perform_capture, 
                        args=(filter_text,), 
                        daemon=True).start()
    
    # Executes packet capture in background
    def perform_capture(self, filter_text):
        try:
            start_packet_capture(
                filter_string=filter_text,
                packet_callback=self.display_packet,
                stop_callback=lambda: self.capture_stopped
            )
        except Exception as e:
            error_msg = str(e)
            self.parent.after(0, lambda: messagebox.showerror("Capture Error", error_msg))
        finally:
            self.parent.after(0, self.capture_finished)
    
    # Displays packet in results
    def display_packet(self, packet_info):
        def update_display():
            self.packet_count += 1
            self.counter_label.config(text=f"Packets Captured: {self.packet_count}")
            
            # Formats packet info
            timestamp = packet_info['timestamp']
            protocol = packet_info['protocol']
            src_ip = packet_info['src_ip']
            dst_ip = packet_info['dst_ip']
            src_port = packet_info['src_port']
            dst_port = packet_info['dst_port']
            summary = packet_info['summary']
            
            # Insert with color tags
            self.results_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.results_text.insert(tk.END, f"{protocol:5} | ", protocol.lower())
            self.results_text.insert(tk.END, f"SRC: {src_ip:15}", "ip")
            
            if src_port != 'N/A':
                self.results_text.insert(tk.END, f":{src_port}", "port")
            
            self.results_text.insert(tk.END, " | ", "other")
            self.results_text.insert(tk.END, f"DST: {dst_ip:15}", "ip")
            
            if dst_port != 'N/A':
                self.results_text.insert(tk.END, f":{dst_port}", "port")
            
            if summary:
                self.results_text.insert(tk.END, f" | {summary}", "other")
            
            self.results_text.insert(tk.END, "\n")
            
            # Auto-scroll to bottom
            self.results_text.see(tk.END)
        
        # Schedules GUI update in main thread
        self.parent.after(0, update_display)
    
    # Stops packet capture
    def stop_capture(self):
        self.capture_stopped = True
        self.stop_button.config(state='disabled')
    
    # Handles the results/captures completion
    def capture_finished(self):
        self.is_capturing = False
        
        self.results_text.insert(tk.END, f"\n{'='*100}\n", "other")
        self.results_text.insert(tk.END, "Capture stopped.\n", "other")
        self.results_text.insert(tk.END, f"Total packets captured: {self.packet_count}\n", "other")
        self.results_text.insert(tk.END, f"{'='*100}\n", "other")
        self.results_text.see(tk.END)
        
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.filter_entry.config(state='normal')