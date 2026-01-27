# gui/password_strength_tab.py
import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, Frame, Label, Button, Entry, Text, Scrollbar, END
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

        # Button frame
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

        # Result area with conditional scrollbar
        frame_result = tk.Frame(self, bg=BG_COLOR, padx=20, pady=18)
        frame_result.pack(fill="both", expand=True)

        self.label_rating = tk.Label(frame_result, text="VERDICT: WAITING...",
                                     font=("Segoe UI", 16, "bold"), fg="#64748b", bg=BG_COLOR)
        self.label_rating.pack(pady=(0, 12))

        # Strength bar
        bar_frame = tk.Frame(frame_result, bg=BG_COLOR)
        bar_frame.pack(fill="x", pady=(0, 12))

        style = ttk.Style()
        try:
            style.theme_use('default')
        except Exception:
            pass
        style.configure("Weak.Horizontal.TProgressbar", troughcolor="#1e293b", background="#ef4444")
        style.configure("Moderate.Horizontal.TProgressbar", troughcolor="#1e293b", background="#f59e0b")
        style.configure("Strong.Horizontal.TProgressbar", troughcolor="#1e293b", background="#22c55e")

        self.progress = ttk.Progressbar(bar_frame, orient="horizontal", length=420, mode="determinate", style="Weak.Horizontal.TProgressbar")
        self.progress.pack(fill="x")
        self.label_percent = tk.Label(bar_frame, text="Strength: 0%", font=("Segoe UI", 10),
                                      fg="#94a3b8", bg=BG_COLOR)
        self.label_percent.pack(anchor="e", pady=(6, 0))

        tk.Frame(frame_result, height=1, bg="#334155").pack(fill="x", pady=8)

        # Scrollable details area with conditional scrollbar
        details_frame = tk.Frame(frame_result, bg=BG_COLOR)
        details_frame.pack(fill="both", expand=True)
        
        self.details_scroll = Scrollbar(details_frame)
        
        self.details_text = Text(details_frame, height=8, font=("Segoe UI", 10),
                                bg=BG_COLOR, fg="#94a3b8", wrap="word", relief="flat",
                                yscrollcommand=self._on_details_scroll, state="disabled")
        self.details_text.pack(side="left", fill="both", expand=True)
        self.details_scroll.config(command=self.details_text.yview)
        
        self.details_text.config(state="normal")
        self.details_text.insert("1.0", "Enter a password to begin analysis.")
        self.details_text.config(state="disabled")

    def _on_details_scroll(self, *args):
        """Show/hide scrollbar based on content"""
        self.details_scroll.set(*args)
        if float(args[0]) > 0.0 or float(args[1]) < 1.0:
            self.details_scroll.pack(side="right", fill="y")
        else:
            self.details_scroll.pack_forget()

    def check_password(self):
        """Analyze password strength"""
        from features.password_strength import evaluate_password_strength
        
        password = self.entry_pass.get().strip()
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password")
            return

        rating, _, messages = evaluate_password_strength(password)
        COLOR_MAP = {"WEAK": "#ef4444", "MODERATE": "#f59e0b", "STRONG": "#22c55e"}
        PROGRESS_MAP = {"WEAK": 22, "MODERATE": 60, "STRONG": 100}
        
        color = COLOR_MAP.get(rating, "#64748b")
        self.label_rating.config(text=f"VERDICT: {rating}", fg=color)

        progress_val = PROGRESS_MAP.get(rating, 0)
        self.progress["value"] = progress_val
        
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
        self.details_text.config(state="normal")
        self.details_text.delete("1.0", END)
        self.details_text.insert("1.0", details_text)
        self.details_text.config(state="disabled")

    def generate_hash(self):
        """Generate SHA-256 hash with copy buttons"""
        import hashlib
        
        password = self.entry_pass.get().strip()
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password first")
            return

        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()

        win = Toplevel(self)
        win.title("Password Hash (SHA-256)")
        win.geometry("520x380")
        win.configure(bg=BG_COLOR)
        win.resizable(False, False)
        win.transient(self.winfo_toplevel())
        win.grab_set()

        header_frame = Frame(win, bg=BG_COLOR, pady=12)
        header_frame.pack(fill="x")
        
        Label(header_frame, text="PASSWORD & HASH", font=("Segoe UI", 14, "bold"),
              fg=ACCENT_COLOR, bg=BG_COLOR).pack()

        pwd_frame = Frame(win, bg=CARD_COLOR, padx=15, pady=12)
        pwd_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        Label(pwd_frame, text="Raw Password:", font=("Segoe UI", 10, "bold"),
              fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w", pady=(0, 4))

        password_entry = Entry(pwd_frame, font=("Consolas", 11), bg="#334155", fg="white", 
                              relief="flat", readonlybackground="#334155")
        password_entry.pack(fill="x", ipady=6)
        password_entry.insert(0, password)
        password_entry.config(state="readonly")

        hash_frame = Frame(win, bg=CARD_COLOR, padx=15, pady=12)
        hash_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        Label(hash_frame, text="SHA-256 Hash:", font=("Segoe UI", 10, "bold"),
              fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w", pady=(0, 4))

        hash_entry = Entry(hash_frame, font=("Consolas", 9), bg="#334155", fg="white", 
                          relief="flat", readonlybackground="#334155")
        hash_entry.pack(fill="x", ipady=6)
        hash_entry.insert(0, digest)
        hash_entry.config(state="readonly")

        warn_frame = Frame(win, bg=BG_COLOR, padx=15)
        warn_frame.pack(fill="x", pady=(0, 10))
        
        warn_text = ("⚠ IMPORTANT: This tool does NOT save the raw password or hash to disk.\n"
                    "Copy the password now if you need it later.")
        Label(warn_frame, text=warn_text, wraplength=480, justify="left",
              font=("Segoe UI", 9), fg="#fca5a5", bg=BG_COLOR).pack()

        btn_container = Frame(win, bg=BG_COLOR, padx=15)
        btn_container.pack(fill="x", pady=(0, 15))

        def copy_password():
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Copied", "Raw password copied to clipboard")

        def copy_hash():
            self.clipboard_clear()
            self.clipboard_append(digest)
            messagebox.showinfo("Copied", "Hash copied to clipboard")

        def copy_as_code():
            code_block = f"```{digest}```"
            self.clipboard_clear()
            self.clipboard_append(code_block)
            messagebox.showinfo("Copied", "Hash copied as code block")

        row1 = Frame(btn_container, bg=BG_COLOR)
        row1.pack(fill="x", pady=(0, 8))
        
        Button(row1, text="Copy Password", command=copy_password,
               bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 10, "bold"),
               relief="flat", cursor="hand2", width=15).pack(side="left", padx=(0, 8))
        
        Button(row1, text="Copy Hash", command=copy_hash,
               bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 10, "bold"),
               relief="flat", cursor="hand2", width=15).pack(side="left", padx=(0, 8))
        
        Button(row1, text="Copy as Code", command=copy_as_code,
               bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 10, "bold"),
               relief="flat", cursor="hand2", width=15).pack(side="left")

        row2 = Frame(btn_container, bg=BG_COLOR)
        row2.pack(fill="x")
        
        Button(row2, text="Close", command=lambda: (win.grab_release(), win.destroy()),
               bg="#94a3b8", fg="#0f172a", font=("Segoe UI", 10, "bold"),
               relief="flat", cursor="hand2").pack(fill="x")