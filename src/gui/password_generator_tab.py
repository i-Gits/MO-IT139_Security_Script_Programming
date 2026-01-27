# gui/password_generator_tab.py
import tkinter as tk
from tkinter import messagebox, Toplevel, Frame, Label, Button, Entry, Text, Scrollbar, END
from tkinter import ttk, StringVar
from datetime import datetime
from features.password_generator import generate_password, hash_password, save_to_file

BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
BTN_HOVER = "#0ea5e9"
SAVE_COLOR = "#22c55e"
INPUT_BG = "#334155"

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

        # Length selection
        length_frame = tk.Frame(frame, bg=CARD_COLOR)
        length_frame.pack(fill="x", pady=10)
        
        tk.Label(length_frame, text="PASSWORD LENGTH (8-16):", 
                 font=("Segoe UI", 10, "bold"), fg=TEXT_MAIN, bg=CARD_COLOR).pack(side="left")
        
        self.length_var = StringVar(value="12")
        length_dropdown = ttk.Combobox(length_frame, textvariable=self.length_var, 
                                       values=[str(i) for i in range(8, 17)],
                                       state="readonly", width=8, font=("Consolas", 10))
        length_dropdown.pack(side="left", padx=(10, 0))

        tk.Button(frame, text="GENERATE & HASH",
                  command=self.generate,
                  bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 11, "bold"),
                  relief="flat", activebackground=BTN_HOVER, cursor="hand2").pack(fill="x", pady=10)

        # Scrollable result area with conditional scrollbar
        result_container = tk.Frame(frame, bg=CARD_COLOR)
        result_container.pack(fill="both", expand=True, pady=12)
        
        self.result_scroll = Scrollbar(result_container)
        
        self.result_text = tk.Text(result_container, height=10, font=("Consolas", 11),
                                   bg="#1e293b", fg=TEXT_MAIN, wrap="word", relief="flat",
                                   yscrollcommand=self._on_text_scroll)
        self.result_text.pack(side="left", fill="both", expand=True)
        self.result_scroll.config(command=self.result_text.yview)

        # Copy buttons row
        copy_frame = tk.Frame(frame, bg=CARD_COLOR)
        copy_frame.pack(fill="x", pady=(8, 0))

        self.btn_copy_password = tk.Button(copy_frame, text="Copy Password", 
                                          command=self.copy_password,
                                          bg=ACCENT_COLOR, fg="#0f172a", 
                                          font=("Segoe UI", 10, "bold"), 
                                          relief="flat", cursor="hand2", 
                                          state="disabled")
        self.btn_copy_password.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.btn_copy_hash = tk.Button(copy_frame, text="Copy Hash", 
                                      command=self.copy_hash,
                                      bg=ACCENT_COLOR, fg="#0f172a", 
                                      font=("Segoe UI", 10, "bold"), 
                                      relief="flat", cursor="hand2",
                                      state="disabled")
        self.btn_copy_hash.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.btn_copy_code = tk.Button(copy_frame, text="Copy as Code", 
                                      command=self.copy_as_code,
                                      bg=ACCENT_COLOR, fg="#0f172a", 
                                      font=("Segoe UI", 10, "bold"), 
                                      relief="flat", cursor="hand2",
                                      state="disabled")
        self.btn_copy_code.pack(side="left", fill="x", expand=True)

        # Save button
        self.btn_save = tk.Button(frame, text="SAVE TO FILE",
                                  command=self.save,
                                  bg=SAVE_COLOR, fg="white", font=("Segoe UI", 10, "bold"),
                                  relief="flat", state="disabled", cursor="hand2")
        self.btn_save.pack(fill="x", pady=(8, 0))

        self.current_data = None

    def _on_text_scroll(self, *args):
        """Show/hide scrollbar based on content"""
        self.result_scroll.set(*args)
        # Show scrollbar only if content is scrollable
        if float(args[0]) > 0.0 or float(args[1]) < 1.0:
            self.result_scroll.pack(side="right", fill="y")
        else:
            self.result_scroll.pack_forget()

    def generate(self):
        """Generate password and display results"""
        try:
            length = int(self.length_var.get())
            password = generate_password(length)
            salt, hashed = hash_password(password)
            
            self.current_data = (password, hashed, salt)

            output = f"Generated Password:\n{password}\n\n"
            output += f"SHA-256 (salted):\n{hashed}\n\n"
            output += f"Salt (hex):\n{salt}\n"

            self.result_text.delete("1.0", END)
            self.result_text.insert("1.0", output)

            # Enable all buttons
            self.btn_save.config(state="normal")
            self.btn_copy_password.config(state="normal")
            self.btn_copy_hash.config(state="normal")
            self.btn_copy_code.config(state="normal")
            
            # Show warning popup
            messagebox.showwarning(
                "⚠ CRITICAL WARNING",
                "Raw password will NOT be saved to file!\n\n"
                "Only hash and salt will be saved.\n\n"
                "Copy the password NOW before closing!"
            )

        except Exception as e:
            self.result_text.delete("1.0", END)
            self.result_text.insert("1.0", f"Error: {str(e)}")
            self.btn_save.config(state="disabled")
            self.btn_copy_password.config(state="disabled")
            self.btn_copy_hash.config(state="disabled")
            self.btn_copy_code.config(state="disabled")

    def copy_password(self):
        """Copy raw password to clipboard"""
        if not self.current_data:
            messagebox.showwarning("Nothing to copy", "Generate a password first")
            return
        password = self.current_data[0]
        self.clipboard_clear()
        self.clipboard_append(password)
        messagebox.showinfo("Copied", "Raw password copied to clipboard")

    def copy_hash(self):
        """Copy hash to clipboard"""
        if not self.current_data:
            messagebox.showwarning("Nothing to copy", "Generate a password first")
            return
        hash_value = self.current_data[1]
        self.clipboard_clear()
        self.clipboard_append(hash_value)
        messagebox.showinfo("Copied", "Hash copied to clipboard")

    def copy_as_code(self):
        """Copy hash as code block"""
        if not self.current_data:
            messagebox.showwarning("Nothing to copy", "Generate a password first")
            return
        hash_value = self.current_data[1]
        code_block = f"```{hash_value}```"
        self.clipboard_clear()
        self.clipboard_append(code_block)
        messagebox.showinfo("Copied", "Hash copied as code block")

    def save(self):
        """Save hash to file (NOT the raw password)"""
        if not self.current_data:
            messagebox.showwarning("Nothing to save", "Generate a password first")
            return

        password, sha256_hash, salt_hex = self.current_data

        if not messagebox.askyesno(
            "Confirm Save", 
            "Save hash for verification?\n\n"
            "⚠ The raw password will NOT be saved.\n"
            "Only the hash and salt will be stored.\n\n"
            "Make sure you've copied the password!"
        ):
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        success = save_to_file(salt_hex, sha256_hash, timestamp, password)
        
        if success:
            messagebox.showinfo("Saved", "Hash saved to data/passwords.txt\n\n⚠ Password was NOT saved!")
            self.btn_save.config(state="disabled")
        else:
            messagebox.showerror("Error", "Could not save — check console")