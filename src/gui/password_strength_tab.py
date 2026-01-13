import tkinter as tk
from tkinter import ttk
from features.password_strength import evaluate_password_strength

# ── Theme colors (your original hackerist style) ──
BG_COLOR = "#0f172a"       # slate-900
CARD_COLOR = "#1e293b"     # slate-800
TEXT_MAIN = "#e2e8f0"      # light grey
ACCENT_COLOR = "#38bdf8"   # sky blue
BTN_HOVER = "#0ea5e9"
COLOR_WEAK = "#ef4444"
COLOR_MOD = "#f59e0b"
COLOR_STRONG = "#22c55e"

COLOR_MAP = {
    "WEAK": COLOR_WEAK,
    "MODERATE": COLOR_MOD,
    "STRONG": COLOR_STRONG
}

class PasswordStrengthTab(tk.Frame):  # ← using tk.Frame instead of ttk for easier bg control
    def __init__(self, parent):
        super().__init__(parent, bg=BG_COLOR)
        self.pack(fill="both", expand=True, padx=20, pady=20)

        # ── Header ──
        frame_header = tk.Frame(self, bg=BG_COLOR, pady=20)
        frame_header.pack(fill="x")

        tk.Label(frame_header,
                 text="PASSECURIST",
                 font=("Segoe UI", 22, "bold"),
                 fg=ACCENT_COLOR,
                 bg=BG_COLOR).pack()

        tk.Label(frame_header,
                 text="Password Strength Analyzer",
                 font=("Segoe UI", 10),
                 fg=TEXT_MAIN,
                 bg=BG_COLOR).pack()

        # ── Input area ──
        frame_input = tk.Frame(self, bg=CARD_COLOR, padx=30, pady=25)
        frame_input.pack(fill="x", pady=10)

        tk.Label(frame_input,
                 text="Enter Password:",
                 font=("Segoe UI", 11),
                 fg=TEXT_MAIN,
                 bg=CARD_COLOR).pack(anchor="w")

        self.entry_pass = tk.Entry(frame_input,
                                   font=("Consolas", 13),
                                   bg="#334155",
                                   fg="white",
                                   insertbackground="white",
                                   relief="flat")
        self.entry_pass.pack(pady=12, ipady=6, fill="x")

        self.btn_check = tk.Button(frame_input,
                                   text="ANALYZE PASSWORD STRENGTH",
                                   command=self.check_password,
                                   bg=ACCENT_COLOR,
                                   fg="#0f172a",
                                   font=("Segoe UI", 10, "bold"),
                                   relief="flat",
                                   activebackground=BTN_HOVER,
                                   cursor="hand2")
        self.btn_check.pack(fill="x", pady=8)

        # Enter key support
        self.entry_pass.bind("<Return>", lambda e: self.check_password())
        self.after(100, lambda: self.entry_pass.focus_set())

        # ── Result area ──
        frame_result = tk.Frame(self, bg=BG_COLOR, padx=20, pady=20)
        frame_result.pack(fill="both", expand=True)

        self.label_rating = tk.Label(frame_result,
                                     text="VERDICT: WAITING...",
                                     font=("Segoe UI", 16, "bold"),
                                     fg="#64748b",
                                     bg=BG_COLOR)
        self.label_rating.pack(pady=(0, 15))

        # Separator
        tk.Frame(frame_result, height=2, bg=CARD_COLOR).pack(fill="x", pady=10)

        self.label_details = tk.Label(frame_result,
                                      text="Enter a password to begin analysis.",
                                      font=("Segoe UI", 10),
                                      fg="#94a3b8",
                                      bg=BG_COLOR,
                                      justify="left",
                                      wraplength=420)
        self.label_details.pack(anchor="w", pady=10)

    def check_password(self):
        password = self.entry_pass.get().strip()

        if not password:
            tk.messagebox.showwarning("Input Required", "Please enter a password")
            return

        rating, color_name, messages = evaluate_password_strength(password)

        color = COLOR_MAP.get(rating, "#64748b")

        self.label_rating.config(text=f"VERDICT: {rating}", fg=color)

        details_text = "\n".join(f"• {msg}" for msg in messages) if messages else "No issues found."
        self.label_details.config(text=details_text)