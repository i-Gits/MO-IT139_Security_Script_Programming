# GUI: Password generator window with hashing and verification

import tkinter as tk
from tkinter import Frame, Label, Button, StringVar, messagebox, Text, Scrollbar, Entry, Toplevel, END
from tkinter import ttk
from datetime import datetime
from features.password_generator import (
    generate_password, 
    hash_password, 
    save_to_file, 
    load_password_entries,
    verify_password_hash
)

# Theme colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
INPUT_BG = "#334155"

class PasswordGeneratorWindow:
    """Password generator window"""
    
    def __init__(self, main_window):
        self.main_window = main_window
        self.window = Toplevel()
        self.setup_window()
        self.create_ui()
    
    def setup_window(self):
        """Configure window settings"""
        self.window.title("Secure Password Generator")
        self.window.geometry("650x750")
        self.window.configure(bg=BG_COLOR)
        self.window.resizable(False, False)
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_ui(self):
        """Create UI components"""
        # Header
        frame_header = Frame(self.window, bg=BG_COLOR, pady=15)
        frame_header.pack()
        Label(frame_header, text="SECURE PASSWORD GENERATOR", 
              font=("Segoe UI", 18, "bold"), fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        Label(frame_header, text="Generate Strong Passwords with SHA-256 Hashing", 
              font=("Segoe UI", 10), fg=TEXT_MAIN, bg=BG_COLOR).pack()
        
        # Length selection and generate button
        frame_gen = Frame(self.window, bg=CARD_COLOR, padx=20, pady=20)
        frame_gen.pack(fill="x", padx=20, pady=10)
        
        Label(frame_gen, text="PASSWORD LENGTH (8-16):", 
              font=("Segoe UI", 11, "bold"), fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        
        self.length_var = StringVar(value="12")
        length_dropdown = ttk.Combobox(frame_gen, textvariable=self.length_var, 
                                       values=[str(i) for i in range(8, 17)],
                                       state="readonly", width=15, font=("Consolas", 11))
        length_dropdown.pack(pady=10, anchor="w")
        
        generate_button = Button(frame_gen, text="GENERATE PASSWORD", command=self.generate_and_save,
                               font=("Segoe UI", 11, "bold"), bg=ACCENT_COLOR, fg=BG_COLOR,
                               relief="flat", cursor="hand2")
        generate_button.pack(fill="x", pady=5)
        
        # Display area
        frame_display = Frame(self.window, bg=BG_COLOR, padx=20)
        frame_display.pack(fill="both", expand=True, pady=10)
        
        Label(frame_display, text="GENERATED PASSWORD & HASH:", 
              font=("Segoe UI", 11, "bold"), fg=TEXT_MAIN, bg=BG_COLOR).pack(anchor="w")
        
        display_frame = Frame(frame_display, bg=CARD_COLOR)
        display_frame.pack(fill="both", expand=True, pady=5)
        
        scrollbar = Scrollbar(display_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.display_text = Text(display_frame, height=14, width=60, 
                                yscrollcommand=scrollbar.set, font=("Consolas", 10),
                                bg=CARD_COLOR, fg=TEXT_MAIN, relief="flat", wrap="word")
        self.display_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.config(command=self.display_text.yview)
        
        self.display_text.insert(END, "Generate a password to get started.\n", "info")
        self.display_text.tag_config("info", foreground=TEXT_MAIN, font=("Segoe UI", 10), justify="center")
        
        # Clear button
        clear_button = Button(frame_display, text="CLEAR DISPLAY", command=self.clear_display,
                             font=("Segoe UI", 9), bg="#ef4444", fg="white",
                             relief="flat", cursor="hand2")
        clear_button.pack(fill="x", pady=5)
        
        # Verify button
        frame_verify = Frame(self.window, bg=BG_COLOR, padx=20)
        frame_verify.pack(fill="x", pady=10)
        
        verify_button = Button(frame_verify, text="VERIFY PASSWORD", command=self.open_verify_window,
                              font=("Segoe UI", 11, "bold"), bg="#22c55e", fg=BG_COLOR,
                              relief="flat", cursor="hand2")
        verify_button.pack(fill="x", pady=5)
        
        # Back button
        btn_back = Button(self.window, text="BACK TO MENU", command=self.on_close,
                         font=("Segoe UI", 10), bg=CARD_COLOR, fg=TEXT_MAIN,
                         relief="flat", cursor="hand2")
        btn_back.pack(pady=10, padx=20, fill="x")
    
    def generate_and_save(self):
        """Generate password, hash it, and save to file"""
        try:
            length = int(self.length_var.get())
            password = generate_password(length)
            salt, hashed = hash_password(password)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Save ONLY hash and salt (not the raw password for security)
            if save_to_file(salt, hashed, timestamp):
                # Display results
                self.display_text.delete(1.0, END)
                self.display_text.insert(END, "=" * 50 + "\n", "center")
                self.display_text.insert(END, "PASSWORD GENERATED!\n", "header")
                self.display_text.insert(END, "=" * 50 + "\n\n", "center")
                
                self.display_text.insert(END, f"PASSWORD: {password}\n\n", "password")
                self.display_text.insert(END, f"SHA-256 HASH:\n{hashed}\n\n", "hash")
                self.display_text.insert(END, f"Generated: {timestamp}\n\n", "info")
                self.display_text.insert(END, "⚠ WARNING ⚠\n", "warning")
                self.display_text.insert(END, "This password is NOT saved!\n", "warning")
                self.display_text.insert(END, "Copy it now before closing.\n\n", "warning")
                self.display_text.insert(END, "✓ Hash saved to file for verification.\n", "success")
                
                # Configure text styling
                self.display_text.tag_config("header", foreground=ACCENT_COLOR, font=("Segoe UI", 14, "bold"), justify="center")
                self.display_text.tag_config("password", foreground="#22c55e", font=("Consolas", 12, "bold"), justify="center")
                self.display_text.tag_config("hash", foreground="#f59e0b", font=("Consolas", 9), justify="center")
                self.display_text.tag_config("warning", foreground="#ef4444", font=("Segoe UI", 10, "bold"), justify="center")
                self.display_text.tag_config("success", foreground="#22c55e", font=("Segoe UI", 11, "bold"), justify="center")
                self.display_text.tag_config("info", foreground=TEXT_MAIN, font=("Segoe UI", 9), justify="center")
                self.display_text.tag_config("center", justify="center")
                
                # Show warning popup
                messagebox.showwarning("⚠ COPY PASSWORD NOW!", 
                    f"Password: {password}\n\n"
                    "⚠ This password is NOT saved to file!\n"
                    "Copy it now before closing this window.\n\n"
                    "Only the hash is saved for verification.")
        
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def clear_display(self):
        """Clear display for security"""
        self.display_text.delete(1.0, END)
        self.display_text.insert(END, "Password cleared for security.\n\n", "info")
        self.display_text.insert(END, "Generate a new password or verify an existing one.", "info")
        self.display_text.tag_config("info", foreground=TEXT_MAIN, font=("Segoe UI", 10), justify="center")
    
    def open_verify_window(self):
        """Open verification window"""
        entries = load_password_entries()
        
        if not entries:
            messagebox.showerror("Error", "No passwords found in the file!")
            return
        
        verify_win = Toplevel()
        verify_win.title("Verify Password")
        verify_win.geometry("500x400")
        verify_win.configure(bg=BG_COLOR)
        verify_win.resizable(False, False)
        
        # Header
        header_frame = Frame(verify_win, bg=BG_COLOR, pady=20)
        header_frame.pack()
        Label(header_frame, text="PASSWORD VERIFICATION", 
              font=("Segoe UI", 16, "bold"), fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        Label(header_frame, text=f"({len(entries)} password(s) available)", 
              font=("Segoe UI", 8, "italic"), fg="#64748b", bg=BG_COLOR).pack(pady=(5, 0))
        
        # Input
        input_frame = Frame(verify_win, bg=CARD_COLOR, padx=30, pady=30)
        input_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        Label(input_frame, text="ENTER PASSWORD:", 
              font=("Segoe UI", 11, "bold"), fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w", pady=(0, 10))
        
        verify_input = StringVar()
        verify_entry = Entry(input_frame, textvariable=verify_input, show="*",
                            font=("Consolas", 12), 
                            bg=INPUT_BG, fg="white", insertbackground="white", relief="flat")
        verify_entry.pack(fill="x", ipady=8, pady=10)
        verify_entry.focus_set()
        
        def verify_action():
            """Verify entered password against saved hashes"""
            password = verify_input.get()
            
            if not password:
                messagebox.showerror("Error", "Please enter a password!")
                return
            
            result = verify_password_hash(password, entries)
            
            if result:
                verify_win.destroy()
                messagebox.showinfo("Success", 
                    f"✓ PASSWORD VERIFIED!\n\nGenerated: {result}")
            else:
                messagebox.showerror("Error", "✗ VERIFICATION FAILED")
        
        verify_entry.bind("<Return>", lambda e: verify_action())
        
        verify_btn = Button(input_frame, text="VERIFY PASSWORD", command=verify_action,
                           font=("Segoe UI", 11, "bold"), bg="#22c55e", fg=BG_COLOR,
                           relief="flat", cursor="hand2")
        verify_btn.pack(fill="x", pady=15)
        
        cancel_btn = Button(input_frame, text="CANCEL", command=verify_win.destroy,
                           font=("Segoe UI", 10), bg=CARD_COLOR, fg=TEXT_MAIN,
                           relief="flat", cursor="hand2")
        cancel_btn.pack(fill="x", pady=(5, 0))
    
    def on_close(self):
        """Returns you to main menu"""
        self.window.destroy()
        self.main_window.deiconify()