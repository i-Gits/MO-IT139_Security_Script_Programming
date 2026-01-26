# gui/password_generator_tab.py
import tkinter as tk
from tkinter import messagebox
from features.password_generator import generate_and_hash_password
from utils.genPassStorage import save_password

BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
BTN_HOVER = "#0ea5e9"
SAVE_COLOR = "#22c55e"

class PasswordGeneratorTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_COLOR)
        self.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        tk.Label(self, text="PASSECURIST", font=("Segoe UI", 22, "bold"),
                 fg=ACCENT_COLOR, bg=BG_COLOR).pack(pady=(10, 5))
        tk.Label(self, text="Password Generator & Hasher", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=(0, 20))

        # Generator section
        frame = tk.Frame(self, bg=CARD_COLOR, padx=30, pady=25)
        frame.pack(fill="x", pady=10)

        tk.Label(frame, text="Generate Strong Password + Hashes",
                 font=("Segoe UI", 14, "bold"), fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w")

        tk.Button(frame, text="GENERATE & HASH",
                  command=self.generate,
                  bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 11, "bold"),
                  relief="flat", activebackground=BTN_HOVER, cursor="hand2").pack(fill="x", pady=10)

        self.result_text = tk.Text(frame, height=10, font=("Consolas", 11),
                                   bg="#1e293b", fg=TEXT_MAIN, wrap="word", relief="flat")
        self.result_text.pack(fill="x", pady=12)

        # Copy buttons for convenience
        copy_frame = tk.Frame(frame, bg=CARD_COLOR)
        copy_frame.pack(fill="x", pady=(0, 8))

        def copy_output():
            content = self.result_text.get("1.0", tk.END).strip()
            if not content:
                messagebox.showwarning("Nothing to copy", "Generate a password first")
                return
            root = self.winfo_toplevel()
            root.clipboard_clear()
            root.clipboard_append(content)
            messagebox.showinfo("Copied", "Generated output copied to clipboard")

        tk.Button(copy_frame, text="Copy Output", command=copy_output,
                  bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2").pack(side="left")

        self.btn_save = tk.Button(frame, text="SAVE GENERATED PASSWORD",
                                  command=self.save,
                                  bg=SAVE_COLOR, fg="white", font=("Segoe UI", 11, "bold"),
                                  relief="flat", state="disabled", cursor="hand2")
        self.btn_save.pack(fill="x", pady=(10, 5))

        self.current_data = None   # (password, sha256, salt_hex)

    def generate(self):
        try:
            password, sha256_hash, salt_hex = generate_and_hash_password()

            self.current_data = (password, sha256_hash, salt_hex)

            output = f"Generated Password:\n{password}\n\n"
            output += f"SHA-256 (salted):\n{sha256_hash}\n\n"
            output += f"Salt (hex):\n{salt_hex}\n"

            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", output)

            self.btn_save.config(state="normal")

        except Exception as e:
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", f"Error: {str(e)}")
            self.btn_save.config(state="disabled")

    def save(self):
        if not self.current_data:
            messagebox.showwarning("Nothing to save", "Generate a password first")
            return

        password, sha256_hash, _ = self.current_data

        if not messagebox.askyesno("Confirm", f"Save this password?\n\n{password}\n\n(only password + SHA-256 will be saved)"):
            return

        success = save_password(password, sha256_hash)
        if success:
            messagebox.showinfo("Saved", "Saved to data/passwords.txt")
            self.btn_save.config(state="disabled")
        else:
            messagebox.showerror("Error", "Could not save — check console")