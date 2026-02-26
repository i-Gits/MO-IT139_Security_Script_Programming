# src/gui/network_port_scanner_tab.py

import tkinter as tk
from tkinter import messagebox, ttk
import threading
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.network_port_scanner import (
    scan_port, 
    validate_host, 
    validate_port_range,
    get_service_name,
    COMMON_PORTS_BY_CATEGORY,
    PORT_PRESETS
)

# PASSECURIST (MS1) Theme Colors
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


class NetworkPortScannerTab:
    """GUI for Network Port Scanner with table results"""
    
    def __init__(self, parent):
        self.parent = parent
        self.parent.configure(bg=BG_COLOR)
        self.is_scanning = False
        self.scan_cancelled = False
        
        # Scrollable canvas
        self.canvas = tk.Canvas(parent, bg=BG_COLOR, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(parent, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=BG_COLOR)
        
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.bind('<Configure>', self.on_canvas_configure)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Mousewheel scrolling
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
        
        tk.Label(header_frame, text="NETWORK PORT SCANNER", 
                font=("Segoe UI", 24, "bold"),
                fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        
        tk.Label(header_frame, text="Scan ports with real-time validation and detailed results",
                font=("Segoe UI", 11), fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=(5, 0))
        
        # Center wrapper for content
        center_wrapper = tk.Frame(self.scrollable_frame, bg=BG_COLOR)
        center_wrapper.pack(fill="both", expand=True, padx=50, pady=10)
        
        # Main container for two columns
        main_container = tk.Frame(center_wrapper, bg=BG_COLOR)
        main_container.pack(fill="both", expand=True)
        
        # Scan Configuration - stretches to fill available space
        left_frame = tk.Frame(main_container, bg=CARD_COLOR, padx=30, pady=25)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        tk.Label(left_frame, text="SCAN CONFIGURATION", 
                font=("Segoe UI", 16, "bold"),
                fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="center", pady=(0, 20))
        
        # Host input
        tk.Label(left_frame, text="Domain / IP Address", 
                font=("Segoe UI", 11, "bold"),
                fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w", pady=(0, 5))
        
        self.host_entry = tk.Entry(left_frame, font=("Consolas", 12),
                                   bg=INPUT_BG, fg=TEXT_MAIN,
                                   insertbackground="white", relief="flat")
        self.host_entry.pack(fill="x", ipady=10, pady=(0, 5))
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.bind('<KeyRelease>', self.validate_host_realtime)
        
        self.host_status = tk.Label(left_frame, text="", 
                                    font=("Segoe UI", 9),
                                    fg=DETAIL_COLOR, bg=CARD_COLOR, anchor="w")
        self.host_status.pack(fill="x", pady=(0, 15))
        
        # Port Type dropdown
        tk.Label(left_frame, text="Port Type", 
                font=("Segoe UI", 11, "bold"),
                fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w", pady=(0, 5))
        
        self.preset_var = tk.StringVar(value="Select")
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Custom.TCombobox',
                       fieldbackground="white",
                       background="white",
                       foreground="#1e293b",
                       arrowcolor="#1e293b",
                       bordercolor="#94a3b8",
                       selectbackground=ACCENT_COLOR,
                       selectforeground="white")
        style.map('Custom.TCombobox',
                 fieldbackground=[('readonly', 'white')],
                 selectbackground=[('readonly', 'white')],
                 selectforeground=[('readonly', '#1e293b')])
        
        preset_dropdown = ttk.Combobox(left_frame, 
                                      textvariable=self.preset_var,
                                      values=list(PORT_PRESETS.keys()),
                                      state="readonly",
                                      style='Custom.TCombobox',
                                      font=("Segoe UI", 11))
        preset_dropdown.pack(fill="x", ipady=8, pady=(0, 15))
        preset_dropdown.bind('<<ComboboxSelected>>', self.on_preset_change)
        
        # Port range inputs
        tk.Label(left_frame, text="Port Range", 
                font=("Segoe UI", 11, "bold"),
                fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w", pady=(0, 5))
        
        port_frame = tk.Frame(left_frame, bg=CARD_COLOR)
        port_frame.pack(fill="x", pady=(0, 5))
        
        self.start_port_entry = tk.Entry(port_frame, font=("Consolas", 12),
                                         bg=INPUT_BG, fg=TEXT_MAIN,
                                         insertbackground="white", relief="flat", width=12)
        self.start_port_entry.pack(side="left", ipady=10)
        self.start_port_entry.insert(0, "20")
        self.start_port_entry.bind('<KeyRelease>', self.validate_ports_realtime)
        
        tk.Label(port_frame, text=" — ", font=("Segoe UI", 14, "bold"),
                fg=TEXT_MAIN, bg=CARD_COLOR).pack(side="left", padx=10)
        
        self.end_port_entry = tk.Entry(port_frame, font=("Consolas", 12),
                                       bg=INPUT_BG, fg=TEXT_MAIN,
                                       insertbackground="white", relief="flat", width=12)
        self.end_port_entry.pack(side="left", ipady=10)
        self.end_port_entry.insert(0, "100")
        self.end_port_entry.bind('<KeyRelease>', self.validate_ports_realtime)
        
        self.port_status = tk.Label(left_frame, text="", 
                                    font=("Segoe UI", 9),
                                    fg=DETAIL_COLOR, bg=CARD_COLOR, anchor="w")
        self.port_status.pack(fill="x", pady=(0, 20))
        
        # Buttons
        button_frame = tk.Frame(left_frame, bg=CARD_COLOR)
        button_frame.pack(fill="x")
        
        self.scan_button = tk.Button(button_frame, text="START SCAN",
                                     command=self.start_scan,
                                     bg=ACCENT_COLOR, fg=BG_COLOR,
                                     font=("Segoe UI", 12, "bold"),
                                     relief="flat", cursor="hand2")
        self.scan_button.pack(side="left", fill="x", expand=True, ipady=12, padx=(0, 5))
        
        self.stop_button = tk.Button(button_frame, text="STOP",
                                     command=self.stop_scan,
                                     bg=ERROR_COLOR, fg="white",
                                     font=("Segoe UI", 12, "bold"),
                                     relief="flat", cursor="hand2",
                                     state="disabled")
        self.stop_button.pack(side="left", fill="x", expand=True, ipady=12, padx=(5, 0))
        
        tk.Button(left_frame, text="CLEAR RESULTS",
                 command=self.clear_results,
                 bg="#475569", fg=TEXT_MAIN,
                 font=("Segoe UI", 10, "bold"),
                 relief="flat", cursor="hand2").pack(fill="x", ipady=10, pady=(10, 0))
        
        # Right column - Common Ports by Category 
        right_frame = tk.Frame(main_container, bg=CARD_COLOR, padx=30, pady=25, width=500)
        right_frame.pack(side="right", fill="y", expand=False)
        right_frame.pack_propagate(False)  # Prevent frame from shrinking
        
        tk.Label(right_frame, text="COMMON PORTS BY SERVICE CATEGORY", 
                font=("Segoe UI", 14, "bold"),
                fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="center", pady=(0, 15))
        
        # Table container with scrollbar - centered with padding
        table_container = tk.Frame(right_frame, bg=CARD_COLOR)
        table_container.pack(fill="both", expand=True)
        
        # Table with scrollbar
        table_scroll = tk.Scrollbar(table_container, orient="vertical")
        
        # Create canvas for scrolling
        table_canvas = tk.Canvas(table_container, bg=CARD_COLOR, 
                                highlightthickness=0, 
                                yscrollcommand=table_scroll.set)
        table_scroll.config(command=table_canvas.yview)
        
        table_frame = tk.Frame(table_canvas, bg=CARD_COLOR)
        table_canvas.create_window((0, 0), window=table_frame, anchor="nw")
        
        # Column weights for proportional resizing - allow stretching
        table_frame.grid_columnconfigure(0, weight=2)  # Category
        table_frame.grid_columnconfigure(1, weight=1)  # Port
        table_frame.grid_columnconfigure(2, weight=6)  # Service
        
        # Table header 
        header_bg = "#ef4444"
        
        tk.Label(table_frame, text="Category", font=("Segoe UI", 10, "bold"),
                fg="white", bg=header_bg, anchor="center").grid(
                    row=0, column=0, sticky="ew", padx=1, pady=(0, 2))
        
        tk.Label(table_frame, text="Port", font=("Segoe UI", 10, "bold"),
                fg="white", bg=header_bg, anchor="center").grid(
                    row=0, column=1, sticky="ew", padx=1, pady=(0, 2))
        
        tk.Label(table_frame, text="Service", font=("Segoe UI", 10, "bold"),
                fg="white", bg=header_bg, anchor="center").grid(
                    row=0, column=2, sticky="ew", padx=1, pady=(0, 2))
        
        # Populate table rows using grid
        row_bg_colors = ["#dbeafe", "#f0f9ff"]  # Alternating colors
        current_row = 1
        
        for category, ports in COMMON_PORTS_BY_CATEGORY.items():
            for port, service in ports:
                bg_color = row_bg_colors[current_row % 2]
                
                # Create labels with grid for proper alignment
                tk.Label(table_frame, text=category, font=("Segoe UI", 9),
                        fg="#1e293b", bg=bg_color, anchor="center").grid(
                            row=current_row, column=0, sticky="ew", padx=1, pady=1, ipady=3)
                
                tk.Label(table_frame, text=port, font=("Consolas", 9, "bold"),
                        fg="#1e293b", bg=bg_color, anchor="center").grid(
                            row=current_row, column=1, sticky="ew", padx=1, pady=1, ipady=3)
                
                tk.Label(table_frame, text=service, font=("Segoe UI", 9),
                        fg="#1e293b", bg=bg_color, anchor="center").grid(
                            row=current_row, column=2, sticky="ew", padx=1, pady=1, ipady=3)
                
                current_row += 1
        
        # Update scroll region
        table_frame.update_idletasks()
        table_canvas.config(scrollregion=table_canvas.bbox("all"))
        
        # Pack canvas and scrollbar with space before scrollbar
        table_canvas.pack(side="left", fill="both", expand=True, padx=(0, 10))
        table_scroll.pack(side="right", fill="y")
        
        # Results section wrapper with centering
        results_wrapper = tk.Frame(self.scrollable_frame, bg=BG_COLOR)
        results_wrapper.pack(fill="both", expand=True, padx=50, pady=(10, 20))
        
        # Results section
        results_frame = tk.Frame(results_wrapper, bg=BG_COLOR)
        results_frame.pack(fill="both", expand=True)
        
        results_header = tk.Frame(results_frame, bg=CARD_COLOR, padx=30, pady=15)
        results_header.pack(fill="x")
        
        tk.Label(results_header, text="SCAN RESULTS", 
                font=("Segoe UI", 14, "bold"),
                fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w")
        
        # Results table
        table_frame_results = tk.Frame(results_frame, bg=CARD_COLOR)
        table_frame_results.pack(fill="both", expand=True)
        
        columns = ("Port Name", "Port #", "Result")
        self.results_tree = ttk.Treeview(table_frame_results, columns=columns, 
                                        show="headings", height=10)
        
        self.results_tree.heading("Port Name", text="Port Name")
        self.results_tree.heading("Port #", text="Port #")
        self.results_tree.heading("Result", text="Result")
        
        # Center align all columns
        self.results_tree.column("Port Name", width=400, anchor="center")
        self.results_tree.column("Port #", width=150, anchor="center")
        self.results_tree.column("Result", width=200, anchor="center")
        
        # Style
        style.configure("Treeview",
                       background=BG_COLOR,
                       foreground=TEXT_MAIN,
                       fieldbackground=BG_COLOR,
                       font=("Consolas", 10))
        style.configure("Treeview.Heading",
                       background=CARD_COLOR,
                       foreground=ACCENT_COLOR,
                       font=("Segoe UI", 11, "bold"))
        
        scrollbar_results = ttk.Scrollbar(table_frame_results, orient="vertical", 
                                 command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar_results.set)
        
        self.results_tree.pack(side="left", fill="both", expand=True, padx=(30, 0), pady=(0, 20))
        scrollbar_results.pack(side="right", fill="y", padx=(0, 30), pady=(0, 20))
        
        # Tags
        self.results_tree.tag_configure("open", foreground=SUCCESS_COLOR, font=("Consolas", 10, "bold"))
        self.results_tree.tag_configure("closed", foreground=DETAIL_COLOR)
    
    def on_preset_change(self, event=None):
        selected = self.preset_var.get()
        
        if selected in PORT_PRESETS:
            preset = PORT_PRESETS[selected]
            self.start_port_entry.delete(0, tk.END)
            self.start_port_entry.insert(0, preset["start"])
            self.end_port_entry.delete(0, tk.END)
            self.end_port_entry.insert(0, preset["end"])
        
        self.validate_ports_realtime()
    
    def validate_host_realtime(self, event=None):
        host = self.host_entry.get().strip()
        
        if not host:
            self.host_status.config(text="⚠ Host required", fg=ERROR_COLOR)
            return False
        
        is_valid, error_msg = validate_host(host)
        
        if is_valid:
            self.host_status.config(text="✓ Valid host", fg=SUCCESS_COLOR)
            return True
        else:
            self.host_status.config(text=f"⚠ {error_msg}", fg=ERROR_COLOR)
            return False
    
    def validate_ports_realtime(self, event=None):
        start_str = self.start_port_entry.get().strip()
        end_str = self.end_port_entry.get().strip()
        
        if not start_str or not end_str:
            self.port_status.config(text="⚠ Both ports required", fg=ERROR_COLOR)
            return False
        
        is_valid, start_port, end_port, error_msg = validate_port_range(start_str, end_str)
        
        if is_valid:
            port_count = end_port - start_port + 1
            self.port_status.config(text=f"✓ Valid range ({port_count} ports)", fg=SUCCESS_COLOR)
            return True
        else:
            self.port_status.config(text=f"⚠ {error_msg}", fg=ERROR_COLOR)
            return False
    
    def clear_results(self):
        """Clear table results"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
    
    def stop_scan(self):
        """Stop scanning/results"""
        self.scan_cancelled = True
        self.stop_button.config(state="disabled")
    
    def start_scan(self):
        """Start scan"""
        if self.is_scanning:
            messagebox.showwarning("Scanning", "Already scanning!")
            return
        
        if not self.validate_host_realtime() or not self.validate_ports_realtime():
            messagebox.showerror("Error", "Fix validation errors first.")
            return
        
        host = self.host_entry.get().strip()
        start_port = int(self.start_port_entry.get().strip())
        end_port = int(self.end_port_entry.get().strip())
        
        self.clear_results()
        
        self.scan_button.config(state='disabled', text="SCANNING...")
        self.stop_button.config(state='normal')
        self.is_scanning = True
        self.scan_cancelled = False
        
        threading.Thread(target=self.perform_scan, 
                        args=(host, start_port, end_port), 
                        daemon=True).start()
    
    def perform_scan(self, host, start_port, end_port):
        """Execute the actual port scanning operation"""
        try:
            # Display scanning message
            print(f"Scanning host: {host}")
            
            for port in range(start_port, end_port + 1):
                if self.scan_cancelled:
                    print("Scan cancelled by user.")
                    break
                
                is_open = scan_port(host, port, timeout=0.5)
                status = "OPEN" if is_open else "CLOSED"
                tag = "open" if is_open else "closed"
                
                # Get service name using the function from network_port_scanner
                service_name = get_service_name(port)
                
                # Console output for real-time feedback
                print(f"Port {port}: {status}")
                
                self.results_tree.insert("", "end", 
                                        values=(service_name, port, status),
                                        tags=(tag,))
            
            if not self.scan_cancelled:
                print("Scan complete.")
                messagebox.showinfo("Scan Complete", f"Scanned {end_port - start_port + 1} ports!")
        
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            print(error_msg)
            messagebox.showerror("Scan Error", error_msg)
        
        finally:
            self.scan_button.config(state='normal', text="START SCAN")
            self.stop_button.config(state='disabled')
            self.is_scanning = False