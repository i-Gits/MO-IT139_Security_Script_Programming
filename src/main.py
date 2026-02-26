# src/main.py
# NOTE: Main application only shows network port scanner and traffic analyzer (just to show a suggested homepage for streamlit ver for all the tools)

import tkinter as tk
from tkinter import font
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# PASSECURIST Theme Colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
CARD_HOVER = "#334155"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
ACCENT_GLOW = "#0ea5e9"

# Card component
class ToolCard(tk.Frame):
    
    def __init__(self, parent, title, description, icon, command):
        super().__init__(parent, bg=CARD_COLOR, cursor="hand2", 
                        highlightthickness=3, highlightbackground=CARD_COLOR)
        
        self.command = command
        self.is_hovered = False
        
        # Grid weight for centering
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Icon 
        self.icon_label = tk.Label(self, text=icon, font=("Segoe UI", 60),
                                   fg=ACCENT_COLOR, bg=CARD_COLOR)
        self.icon_label.grid(row=1, column=0, pady=(40, 20))
        
        # Title
        self.title_label = tk.Label(self, text=title, 
                                    font=("Segoe UI", 18, "bold"),
                                    fg=TEXT_MAIN, bg=CARD_COLOR)
        self.title_label.grid(row=2, column=0, pady=(0, 10))
        
        # Description
        self.desc_label = tk.Label(self, text=description,
                                   font=("Segoe UI", 11),
                                   fg="#94a3b8", bg=CARD_COLOR,
                                   wraplength=300, justify="center")
        self.desc_label.grid(row=3, column=0, pady=(0, 40), padx=30)
        
        # Bind hover events to all widgets
        for widget in [self, self.icon_label, self.title_label, self.desc_label]:
            widget.bind("<Enter>", self.on_enter)
            widget.bind("<Leave>", self.on_leave)
            widget.bind("<Button-1>", self.on_click)
    
    def on_enter(self, event):
        # Handle mouse enter - adds glow effect
        self.config(highlightbackground=ACCENT_GLOW, bg=CARD_HOVER)
        self.icon_label.config(bg=CARD_HOVER, fg=ACCENT_GLOW)
        self.title_label.config(bg=CARD_HOVER)
        self.desc_label.config(bg=CARD_HOVER)
        self.is_hovered = True
    
    def on_leave(self, event):
        # Handles mouse leave - removes glow effect
        self.config(highlightbackground=CARD_COLOR, bg=CARD_COLOR)
        self.icon_label.config(bg=CARD_COLOR, fg=ACCENT_COLOR)
        self.title_label.config(bg=CARD_COLOR)
        self.desc_label.config(bg=CARD_COLOR)
        self.is_hovered = False
    
    def on_click(self, event):
        # Handles card click
        if self.command:
            self.command()


class PassecuristApp:
    
    # Homepage
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ PASSECURIST - Network Security Tools")
        self.root.geometry("1400x800")
        self.root.configure(bg=BG_COLOR)
        
        # Center window on screen
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        self.setup_homepage()
    
    def setup_homepage(self):

        # Header/Banner
        header_frame = tk.Frame(self.root, bg=BG_COLOR)
        header_frame.pack(fill="x", pady=(40, 20))
        
        tk.Label(header_frame, text="🛡️ PASSECURIST", 
                font=("Segoe UI", 36, "bold"),
                fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        
        tk.Label(header_frame, 
                text="Basic Network Security & Analysis Tools",
                font=("Segoe UI", 14),
                fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=(10, 5))
        
        tk.Label(header_frame, 
                text="Monitor, analyze, and secure your network infrastructure with powerful tools",
                font=("Segoe UI", 11),
                fg="#94a3b8", bg=BG_COLOR).pack()
        
        # Cards container
        cards_frame = tk.Frame(self.root, bg=BG_COLOR)
        cards_frame.pack(expand=True, fill="both", padx=100, pady=40)
        
        # Configure grid for centering
        cards_frame.grid_columnconfigure(0, weight=1)
        cards_frame.grid_columnconfigure(1, weight=1)
        cards_frame.grid_rowconfigure(0, weight=1)
        
        # Card 1: Network Port Scanner
        port_scanner_card = ToolCard(
            cards_frame,
            title="Network Port Scanner",
            description="Scan TCP ports on any host with real-time validation, service identification, and detailed results.",
            icon="🔍",
            command=self.open_port_scanner
        )
        port_scanner_card.grid(row=0, column=0, padx=20, sticky="nsew")
        
        # Card 2: Network Traffic Analyzer
        traffic_analyzer_card = ToolCard(
            cards_frame,
            title="Network Traffic Analyzer",
            description="Capture and analyze real-time network packets with protocol filtering and detailed packet inspection.",
            icon="📊",
            command=self.open_traffic_analyzer
        )
        traffic_analyzer_card.grid(row=0, column=1, padx=20, sticky="nsew")
        
        # Footer
        footer_frame = tk.Frame(self.root, bg=BG_COLOR)
        footer_frame.pack(side="bottom", fill="x", pady=20)
        
        tk.Label(footer_frame, 
                text="Security Script Programming 2026 | Group 8",
                font=("Segoe UI", 9),
                fg="#64748b", bg=BG_COLOR).pack()
    
    def open_port_scanner(self):

        # Hide homepage
        self.root.withdraw()
        
        scanner_window = tk.Toplevel(self.root)
        scanner_window.title("🛡️ PASSECURIST - Network Port Scanner")
        scanner_window.geometry("1600x900")
        scanner_window.configure(bg=BG_COLOR)
        
        # Add back button at the top
        back_frame = tk.Frame(scanner_window, bg=BG_COLOR)
        back_frame.pack(fill="x", padx=20, pady=10)
        
        back_button = tk.Button(
            back_frame,
            text="← Back to Homepage",
            command=lambda: self.close_tool_window(scanner_window),
            bg=CARD_COLOR,
            fg=ACCENT_COLOR,
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            cursor="hand2",
            padx=20,
            pady=10
        )
        back_button.pack(side="left")
        
        # Content frame for the tool
        content_frame = tk.Frame(scanner_window, bg=BG_COLOR)
        content_frame.pack(fill="both", expand=True)
        
        from gui.network_port_scanner_tab import NetworkPortScannerTab
        NetworkPortScannerTab(content_frame)
        
        # Handle window close button (X)
        scanner_window.protocol("WM_DELETE_WINDOW", lambda: self.close_tool_window(scanner_window))
    
    def open_traffic_analyzer(self):

        # Hide homepage
        self.root.withdraw()
        
        analyzer_window = tk.Toplevel(self.root)
        analyzer_window.title("🛡️ PASSECURIST - Network Traffic Analyzer")
        analyzer_window.geometry("1600x900")
        analyzer_window.configure(bg=BG_COLOR)
        
        # Add back button at the top
        back_frame = tk.Frame(analyzer_window, bg=BG_COLOR)
        back_frame.pack(fill="x", padx=20, pady=10)
        
        back_button = tk.Button(
            back_frame,
            text="← Back to Homepage",
            command=lambda: self.close_tool_window(analyzer_window),
            bg=CARD_COLOR,
            fg=ACCENT_COLOR,
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            cursor="hand2",
            padx=20,
            pady=10
        )
        back_button.pack(side="left")
        
        # Content frame for the tool
        content_frame = tk.Frame(analyzer_window, bg=BG_COLOR)
        content_frame.pack(fill="both", expand=True)
        
        from gui.network_traffic_analyzer_tab import NetworkTrafficAnalyzerTab
        NetworkTrafficAnalyzerTab(content_frame)
        
        # Handle window close button 
        analyzer_window.protocol("WM_DELETE_WINDOW", lambda: self.close_tool_window(analyzer_window))
    
    def close_tool_window(self, tool_window):
        tool_window.destroy()
        self.root.deiconify()  # Show homepage again


if __name__ == "__main__":
    root = tk.Tk()
    app = PassecuristApp(root)
    root.mainloop()