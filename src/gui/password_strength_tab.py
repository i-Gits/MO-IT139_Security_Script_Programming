# gui/password_strength_tab.py

import tkinter as tk
from tkinter import messagebox
from features.password_strength import evaluate_password_strength
from features.password_generator import generate_and_hash_password
from utils.genPassStorage import save_password

# ── Theme colors ──
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

        # ── Header ──
        frame_header = tk.Frame(self, bg=BG_COLOR, pady=20)
        frame_header.pack(fill="x")

        tk.Label(frame_header, text="PASSECURIST", 
                 font=("Segoe UI", 22, "bold"), fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        tk.Label(frame_header, text="Password Strength & Generator", 
                 font=("Segoe UI", 10), fg=TEXT_MAIN, bg=BG_COLOR).pack()

        # ── SECTION 1: Password Strength Checker ──
        self._create_strength_section()

        # ── SECTION 2: Password Generator & Hasher ──
        self._create_generator_section()

        # Focus on entry after load
        self.after(100, lambda: self.entry_pass.focus_set())

    def _create_strength_section(self):
        """Create the password strength checking section"""
        frame = tk.Frame(self, bg=CARD_COLOR, padx=30, pady=20)
        frame.pack(fill="x", pady=10)

        tk.Label(frame, text="Check Password Strength", font=("Segoe UI", 13, "bold"),
                 fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w")

        tk.Label(frame, text="Enter Password:", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w", pady=(10, 0))

        self.entry_pass = tk.Entry(frame, font=("Consolas", 13),
                                   bg="#334155", fg="white", insertbackground="white", relief="flat")
        self.entry_pass.pack(pady=10, ipady=6, fill="x")

        tk.Button(frame, text="ANALYZE PASSWORD STRENGTH",
                  command=self.check_password,
                  bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 10, "bold"),
                  relief="flat", activebackground=BTN_HOVER, cursor="hand2").pack(fill="x", pady=5)

        self.entry_pass.bind("<Return>", lambda e: self.check_password())

        self.label_rating = tk.Label(frame, text="VERDICT: WAITING...",
                                     font=("Segoe UI", 16, "bold"), fg="#64748b", bg=CARD_COLOR)
        self.label_rating.pack(pady=(15, 5))

        tk.Frame(frame, height=2, bg=CARD_COLOR).pack(fill="x", pady=10)

        self.label_details = tk.Label(frame, text="Enter a password to begin analysis.",
                                      font=("Segoe UI", 10), fg="#94a3b8", bg=CARD_COLOR,
                                      justify="left", wraplength=420)
        self.label_details.pack(anchor="w", pady=10)

    def _create_generator_section(self):
        """Create the random password generation + hashing section"""
        frame = tk.Frame(self, bg=CARD_COLOR, padx=30, pady=25)
        frame.pack(fill="x", pady=(30, 10))

        tk.Label(frame, text="Generate Strong Password + Hashes",
                 font=("Segoe UI", 13, "bold"), fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w")
        # The generate button
        tk.Button(frame, text="GENERATE & HASH",
                  command=self.generate_and_display,
                  bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 11, "bold"),
                  relief="flat", activebackground=BTN_HOVER, cursor="hand2").pack(fill="x", pady=5)

        # Result display area
        self.gen_result = tk.Text(frame, height=10, font=("Consolas", 11),
                                  bg="#1e293b", fg=TEXT_MAIN, wrap="word", relief="flat")
        self.gen_result.pack(fill="x", pady=12)

        #Save button
        self.btn_save = tk.Button(frame,
                                 text="SAVE GENERATED PASSWORD",
                                 command=self.save_generated_password,
                                 bg="#22c55e",  # green to indicate success/save
                                 fg="white",
                                 font=("Segoe UI", 10, "bold"),
                                 relief="flat",
                                 state="disabled", 
                                 cursor="hand2")
        self.btn_save.pack(fill="x", pady=(10, 5))

    #Strength checking logic
    def check_password(self):
        password = self.entry_pass.get().strip()

        if not password:
            messagebox.showwarning("Input Required", "Please enter a password")
            return

        rating, color_name, messages = evaluate_password_strength(password)
        color = COLOR_MAP.get(rating, "#64748b")

        self.label_rating.config(text=f"VERDICT: {rating}", fg=color)

        details_text = "\n".join(f"• {msg}" for msg in messages) if messages else "No issues found."
        self.label_details.config(text=details_text)

    #Generation + Hashing logic
    def generate_and_display(self):
        """Generate a random password and display its hashes"""
        try:
            password, sha256_hash, salt_hex = generate_and_hash_password()

            self.current_generated_password = (sha256_hash)

            output = f"Generated Password:\n{password}\n\n"
            output += f"SHA-256 (salted):\n{sha256_hash}\n\n"
            output += f"Salt (hex):\n{salt_hex}\n\n"

            self.gen_result.delete("1.0", tk.END)
            self.gen_result.insert("1.0", output)

            self.btn_save.config(state="normal")
        except Exception as e:
            self.gen_result.delete("1.0", tk.END)
            self.gen_result.insert("1.0", f"Error: {str(e)}")

    def save_generated_password(self):
        if not self.current_generated_password:
            messagebox.showwarning("No Password", "Generate a password first!")
            return

        sha256_hash = self.current_generated_password

        confirm = messagebox.askyesno(
            "Confirm Save",
            f"Save this entry?\n\n"
            f"SHA-256: {sha256_hash[:16]}...\n" 
            "Note: This is plain text storage!"
        )

        if confirm:
            success = save_password(sha256_hash)
            if success:
                messagebox.showinfo("Saved", "Password saved successfully to data/passwords.txt")
                self.btn_save.config(state="disabled") 
              
            else:
                messagebox.showerror("Save Failed", "Could not save the password. Check console for details.")