# Main menu with option to choose between password tools

import tkinter as tk
from tkinter import Frame, Label, Button
from gui.password_strength_tab import PasswordStrengthWindow
from gui.password_generator_tab import PasswordGeneratorWindow

# Theme colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"

class MainMenu:
    """Main menu for Password Security Toolkit"""
    
    def __init__(self, root):
        self.root = root
        self.create_menu()
    
    def create_menu(self):
        """Create main menu window/GUI"""
        # Header
        frame_header = Frame(self.root, bg=BG_COLOR, pady=30)
        frame_header.pack()
        
        Label(frame_header, text="PASSWORD SECURITY TOOLKIT", 
              font=("Segoe UI", 24, "bold"), fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        Label(frame_header, text="Analyze Password Strength or Generate a Secure Password", 
              font=("Segoe UI", 11), fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=10)
        
        # Button container
        frame_buttons = Frame(self.root, bg=BG_COLOR, padx=50)
        frame_buttons.pack(expand=True, pady=20)
        
        # Button 1: Password Strength Checker
        btn_strength = Button(frame_buttons, text="CHECK PASSWORD STRENGTH",
                             command=self.open_strength_window,
                             font=("Segoe UI", 13, "bold"), bg=CARD_COLOR, fg=TEXT_MAIN,
                             relief="flat", cursor="hand2", height=3)
        btn_strength.pack(fill="x", pady=15)
        
        # Hover effects for button 1 - cyan
        btn_strength.bind("<Enter>", lambda e: btn_strength.config(bg=ACCENT_COLOR, fg=BG_COLOR))
        btn_strength.bind("<Leave>", lambda e: btn_strength.config(bg=CARD_COLOR, fg=TEXT_MAIN))
        
        # Button 2: Password Generator
        btn_generator = Button(frame_buttons, text="GENERATE RANDOM PASSWORD",
                              command=self.open_generator_window,
                              font=("Segoe UI", 13, "bold"), bg=CARD_COLOR, fg=TEXT_MAIN,
                              relief="flat", cursor="hand2", height=3)
        btn_generator.pack(fill="x", pady=15)
        
        # Hover effects for button 2 - cyan
        btn_generator.bind("<Enter>", lambda e: btn_generator.config(bg=ACCENT_COLOR, fg=BG_COLOR))
        btn_generator.bind("<Leave>", lambda e: btn_generator.config(bg=CARD_COLOR, fg=TEXT_MAIN))
        
        # Quit button
        quit_button = Button(self.root, text="QUIT", command=self.root.quit,
                            font=("Segoe UI", 10), bg=CARD_COLOR, fg=TEXT_MAIN,
                            relief="flat", cursor="hand2")
        quit_button.pack(pady=20, padx=50, fill="x")
    
    def open_strength_window(self):
        """Open password strength checker"""
        self.root.withdraw()
        PasswordStrengthWindow(self.root)
    
    def open_generator_window(self):
        """Open password generator"""
        self.root.withdraw()
        PasswordGeneratorWindow(self.root)