# gui/password_strength_tab.py
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
from features.password_strength import evaluate_password_strength

# Theme colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
BTN_HOVER = "#0ea5e9"
COLOR_WEAK = "#ef4444"
COLOR_MOD = "#f59e0b"
COLOR_STRONG = "#22c55e"

COLOR_MAP = {"WEAK": COLOR_WEAK, "MODERATE": COLOR_MOD, "STRONG": COLOR_STRONG}
PROGRESS_MAP = {"WEAK": 22, "MODERATE": 60, "STRONG": 100}


class PasswordStrengthTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_COLOR)
        self.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        tk.Label(self, text="PASSECURIST", font=("Segoe UI", 22, "bold"),
                 fg=ACCENT_COLOR, bg=BG_COLOR).pack(pady=(10, 5))
        tk.Label(self, text="Password Strength Analyzer", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=(0, 12))

        # Input card
        frame_input = tk.Frame(self, bg=CARD_COLOR, padx=20, pady=18)
        frame_input.pack(fill="x", pady=8)

        tk.Label(frame_input, text="Enter Password:", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")

        self.entry_pass = tk.Entry(frame_input, font=("Consolas", 13),
                                   bg="#334155", fg="white", insertbackground="white",
                                   relief="flat")
        self.entry_pass.pack(pady=10, ipady=6, fill="x")

        btn_frame = tk.Frame(frame_input, bg=CARD_COLOR)
        btn_frame.pack(fill="x", pady=(6, 0))

        self.btn_check = tk.Button(btn_frame, text="ANALYZE PASSWORD STRENGTH",
                                   command=self.check_password,
                                   bg=ACCENT_COLOR, fg="#0f172a",
                                   font=("Segoe UI", 10, "bold"), relief="flat",
                                   activebackground=BTN_HOVER, cursor="hand2")
        self.btn_check.pack(side="left", fill="x", expand=True)

        self.btn_hash = tk.Button(btn_frame, text="GENERATE HASH",
                                  command=self.generate_hash, bg="#94a3b8",
                                  fg="#0f172a", font=("Segoe UI", 10, "bold"),
                                  relief="flat", activebackground="#bfcfe0", cursor="hand2")
        self.btn_hash.pack(side="left", padx=(8, 0))

        self.entry_pass.bind("<Return>", lambda e: self.check_password())
        self.after(100, lambda: self.entry_pass.focus_set())

        # Result area
        frame_result = tk.Frame(self, bg=BG_COLOR, padx=20, pady=18)
        frame_result.pack(fill="both", expand=True)

        self.label_rating = tk.Label(frame_result, text="VERDICT: WAITING...",
                                     font=("Segoe UI", 16, "bold"), fg="#64748b", bg=BG_COLOR)
        self.label_rating.pack(pady=(0, 12))

        # Strength bar
        bar_frame = tk.Frame(frame_result, bg=BG_COLOR)
        bar_frame.pack(fill="x", pady=(0, 12))

        # Create styles for colored progress bars (used when updating strength)
        style = ttk.Style()
        try:
            style.theme_use('default')
        except Exception:
            pass
        style.configure("Weak.Horizontal.TProgressbar", troughcolor="#1e293b", background=COLOR_WEAK)
        style.configure("Moderate.Horizontal.TProgressbar", troughcolor="#1e293b", background=COLOR_MOD)
        style.configure("Strong.Horizontal.TProgressbar", troughcolor="#1e293b", background=COLOR_STRONG)

        self.progress = ttk.Progressbar(bar_frame, orient="horizontal", length=420, mode="determinate", style="Weak.Horizontal.TProgressbar")
        self.progress.pack(fill="x")
        self.label_percent = tk.Label(bar_frame, text="Strength: 0%", font=("Segoe UI", 10),
                                      fg="#94a3b8", bg=BG_COLOR)
        self.label_percent.pack(anchor="e", pady=(6, 0))

        tk.Frame(frame_result, height=1, bg="#334155").pack(fill="x", pady=8)

        self.label_details = tk.Label(frame_result, text="Enter a password to begin analysis.",
                                      font=("Segoe UI", 10), fg="#94a3b8", bg=BG_COLOR,
                                      justify="left", wraplength=420)
        self.label_details.pack(anchor="w", pady=6)

    def check_password(self):
        password = self.entry_pass.get().strip()
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password")
            return

        rating, _, messages = evaluate_password_strength(password)
        color = COLOR_MAP.get(rating, "#64748b")

        self.label_rating.config(text=f"VERDICT: {rating}", fg=color)

        # progress mapping
        progress_val = PROGRESS_MAP.get(rating, 0)
        self.progress["value"] = progress_val
        # apply corresponding style so the bar color matches verdict
        style_name = {
            "WEAK": "Weak.Horizontal.TProgressbar",
            "MODERATE": "Moderate.Horizontal.TProgressbar",
            "STRONG": "Strong.Horizontal.TProgressbar",
        }.get(rating, "Weak.Horizontal.TProgressbar")
        try:
            self.progress.configure(style=style_name)
        except Exception:
            pass
        self.label_percent.config(text=f"Strength: {int(progress_val)}%")

        details_text = "\n".join(f"• {m}" for m in messages) if messages else "No issues found."
        self.label_details.config(text=details_text)

    def generate_hash(self):
        password = self.entry_pass.get().strip()
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password first")
            return

        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()

        # modal popup
        win = tk.Toplevel(self)
        win.title("Password Hash (SHA-256)")
        win.configure(bg=BG_COLOR)
        win.resizable(False, False)
        win.transient(self.winfo_toplevel())
        win.grab_set()

        tk.Label(win, text="SHA-256 Hash:", font=("Segoe UI", 10, "bold"),
                 fg=TEXT_MAIN, bg=BG_COLOR).pack(anchor="w", padx=12, pady=(12, 4))

        hash_entry = tk.Entry(win, font=("Consolas", 11), bg="#334155", fg="white", relief="flat")
        hash_entry.pack(fill="x", padx=12, pady=(0, 8))
        hash_entry.insert(0, digest)
        hash_entry.select_range(0, "end")

        warn_text = ("IMPORTANT: This tool does NOT save the raw password or the hash to disk. "
                     "If you need the raw password, copy it now before closing this dialog.")
        tk.Label(win, text=warn_text, wraplength=420, justify="left",
                 font=("Segoe UI", 9), fg="#fca5a5", bg=BG_COLOR).pack(anchor="w", padx=12, pady=(0, 10))

        btn_frame = tk.Frame(win, bg=BG_COLOR)
        btn_frame.pack(fill="x", padx=12, pady=(0, 12))

        def copy_hash():
            self.clipboard_clear()
            self.clipboard_append(digest)
            messagebox.showinfo("Copied", "Hash copied to clipboard")

        def copy_as_code():
            code_block = f"```{digest}```"
            self.clipboard_clear()
            self.clipboard_append(code_block)
            messagebox.showinfo("Copied", "Hash copied as code block to clipboard")

        tk.Button(btn_frame, text="Copy Hash", command=copy_hash,
                  bg=ACCENT_COLOR, fg="#0f172a", relief="flat", cursor="hand2").pack(side="left")
        tk.Button(btn_frame, text="Copy as Code", command=copy_as_code,
                  bg=ACCENT_COLOR, fg="#0f172a", relief="flat", cursor="hand2").pack(side="left", padx=(8, 0))
        tk.Button(btn_frame, text="Close", command=lambda: (win.grab_release(), win.destroy()),
                  bg="#94a3b8", fg="#0f172a", relief="flat", cursor="hand2").pack(side="right")