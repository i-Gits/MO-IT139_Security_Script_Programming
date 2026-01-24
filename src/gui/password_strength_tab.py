# gui/password_strength_tab.py
import tkinter as tk
from tkinter import messagebox
from features.password_strength import evaluate_password_strength

BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
BTN_HOVER = "#0ea5e9"
COLOR_WEAK = "#ef4444"
COLOR_MOD = "#f59e0b"
COLOR_STRONG = "#22c55e"

COLOR_MAP = {
    "WEAK": COLOR_WEAK,
    "MODERATE": COLOR_MOD,
    "STRONG": COLOR_STRONG
}

class PasswordStrengthTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_COLOR)
        self.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        tk.Label(self, text="PASSECURIST", font=("Segoe UI", 22, "bold"),
                 fg=ACCENT_COLOR, bg=BG_COLOR).pack(pady=(10, 5))
        tk.Label(self, text="Password Strength Analyzer", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=(0, 20))

        # Strength section
        frame = tk.Frame(self, bg=CARD_COLOR, padx=30, pady=25)
        frame.pack(fill="x", pady=10)

        tk.Label(frame, text="Check Password Strength", font=("Segoe UI", 14, "bold"),
                 fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w")

        tk.Label(frame, text="Enter Password:", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w", pady=(12, 0))

        self.entry = tk.Entry(frame, font=("Consolas", 13),
                              bg="#334155", fg="white", insertbackground="white", relief="flat")
        self.entry.pack(pady=10, ipady=6, fill="x")

        tk.Button(frame, text="ANALYZE STRENGTH",
                  command=self.check,
                  bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 11, "bold"),
                  relief="flat", activebackground=BTN_HOVER, cursor="hand2").pack(fill="x", pady=8)

        self.entry.bind("<Return>", lambda e: self.check())

        self.rating_label = tk.Label(frame, text="VERDICT: WAITING...",
                                     font=("Segoe UI", 16, "bold"), fg="#64748b", bg=CARD_COLOR)
        self.rating_label.pack(pady=(20, 5))

        tk.Frame(frame, height=1, bg="#334155").pack(fill="x", pady=8)

        self.details_label = tk.Label(frame, text="Enter a password to begin...",
                                      font=("Segoe UI", 10), fg="#94a3b8", bg=CARD_COLOR,
                                      justify="left", wraplength=420)
        self.details_label.pack(anchor="w", pady=10)

        self.after(150, lambda: self.entry.focus_set())

    def check(self):
        pwd = self.entry.get().strip()
        if not pwd:
            messagebox.showwarning("Input Required", "Please enter a password")
            return

        rating, _, messages = evaluate_password_strength(pwd)
        color = COLOR_MAP.get(rating, "#64748b")

        self.rating_label.config(text=f"VERDICT: {rating}", fg=color)
        text = "\n".join(f"• {m}" for m in messages) if messages else "No issues found."
        self.details_label.config(text=text)