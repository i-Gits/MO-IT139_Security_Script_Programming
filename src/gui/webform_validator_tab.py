# gui/web_validator_tab.py
import tkinter as tk
from tkinter import ttk, messagebox
from features.webform_validator import validate_inputs  # ← your logic file

# Theme colors (same as before)
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
BTN_HOVER = "#0ea5e9"
COLOR_GOOD = "#22c55e"
COLOR_WARNING = "#f59e0b"
COLOR_BAD = "#ef4444"

class WebValidatorTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_COLOR)
        self.pack(fill="both", expand=True, padx=20, pady=20)

        # ── Header ──
        tk.Label(self, text="PASSECURIST", font=("Segoe UI", 22, "bold"),
                 fg=ACCENT_COLOR, bg=BG_COLOR).pack(pady=(10, 5))

        tk.Label(self, text="Web Form / Input Validator",
                 font=("Segoe UI", 11), fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=(0, 20))

        # ── Input card ──
        frame = tk.Frame(self, bg=CARD_COLOR, padx=30, pady=25)
        frame.pack(fill="both", expand=True, pady=10)

        tk.Label(frame, text="Fill in the form fields to validate",
                 font=("Segoe UI", 13, "bold"), fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w", pady=(0, 15))

        # Full Name
        tk.Label(frame, text="Full Name", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        self.entry_name = tk.Entry(frame, font=("Consolas", 12),
                                   bg="#334155", fg=TEXT_MAIN,
                                   insertbackground="white", relief="flat")
        self.entry_name.pack(fill="x", pady=(4, 12), ipady=6)

        # Email Address
        tk.Label(frame, text="Email Address", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        self.entry_email = tk.Entry(frame, font=("Consolas", 12),
                                    bg="#334155", fg=TEXT_MAIN,
                                    insertbackground="white", relief="flat")
        self.entry_email.pack(fill="x", pady=(4, 12), ipady=6)

        # Username
        tk.Label(frame, text="Username", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        self.entry_username = tk.Entry(frame, font=("Consolas", 12),
                                       bg="#334155", fg=TEXT_MAIN,
                                       insertbackground="white", relief="flat")
        self.entry_username.pack(fill="x", pady=(4, 12), ipady=6)

        # Message / Comment
        tk.Label(frame, text="Message / Comment", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        self.text_message = tk.Text(frame, height=5, font=("Consolas", 12),
                                    bg="#334155", fg=TEXT_MAIN,
                                    insertbackground="white", wrap="word", relief="flat")
        self.text_message.pack(fill="both", expand=True, pady=(4, 16), ipady=6)

        # Buttons
        btn_frame = tk.Frame(frame, bg=CARD_COLOR)
        btn_frame.pack(fill="x", pady=(10, 0))

        tk.Button(btn_frame, text="VALIDATE FORM",
                  command=self.validate_form,
                  bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 11, "bold"),
                  relief="flat", activebackground=BTN_HOVER, cursor="hand2").pack(side="left", padx=(0, 10))

        tk.Button(btn_frame, text="CLEAR ALL",
                  command=self.clear_form,
                  bg="#475569", fg=TEXT_MAIN, font=("Segoe UI", 11, "bold"),
                  relief="flat", activebackground="#334155", cursor="hand2").pack(side="left")

        # ── Result area ──
        self.result_label = tk.Label(frame, text="Validation result will appear here...",
                                     font=("Segoe UI", 11), fg="#94a3b8", bg=CARD_COLOR,
                                     justify="left", wraplength=520, anchor="w")
        self.result_label.pack(anchor="w", pady=(25, 10))

        self.details_text = tk.Text(frame, height=8, font=("Consolas", 11),
                                    bg="#1e293b", fg=TEXT_MAIN,
                                    wrap="word", relief="flat", state="disabled")
        self.details_text.pack(fill="x", pady=8)

        # Tag colors
        self.details_text.tag_configure("good", foreground=COLOR_GOOD)
        self.details_text.tag_configure("warning", foreground=COLOR_WARNING)
        self.details_text.tag_configure("bad", foreground=COLOR_BAD)

    def validate_form(self):
        # Collect all fields
        data = {
            "Full Name": self.entry_name.get().strip(),
            "Email Address": self.entry_email.get().strip(),
            "Username": self.entry_username.get().strip(),
            "Message / Comment": self.text_message.get("1.0", tk.END).strip()
        }

        # Skip empty fields for validation (or you can force them required)
        inputs_to_check = [v for v in data.values() if v]

        if not inputs_to_check:
            messagebox.showwarning("Empty Form", "Please fill in at least one field.")
            return

        # Flatten to one string with labels (for your existing validate_inputs)
        raw_text = "\n".join(f"{k}: {v}" for k, v in data.items() if v)

        result = validate_inputs(raw_text)

        # Update summary
        self.result_label.config(text=result["summary"], fg=result["summary_color"])

        # Show detailed per-line results
        self.details_text.config(state="normal")
        self.details_text.delete("1.0", tk.END)

        for line in result["lines"]:
            display = f"{line['kind']} → {line['value']}\n   {line['message']}\n\n"
            self.details_text.insert(tk.END, display, line["severity"])

        self.details_text.config(state="disabled")

    def clear_form(self):
        self.entry_name.delete(0, tk.END)
        self.entry_email.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.text_message.delete("1.0", tk.END)
        self.result_label.config(text="Validation result will appear here...", fg="#94a3b8")
        self.details_text.config(state="normal")
        self.details_text.delete("1.0", tk.END)
        self.details_text.config(state="disabled")