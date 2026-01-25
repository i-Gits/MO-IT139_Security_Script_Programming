# GUI: Password strength analyzer 

import tkinter as tk
from tkinter import Frame, Label, Entry, Button, messagebox, Toplevel
from features.password_strength import evaluate_password_strength

# Theme colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"

class PasswordStrengthWindow:
    """Password strength analyzer window"""
    
    def __init__(self, main_window):
        self.main_window = main_window
        self.window = Toplevel()
        self.setup_window()
        self.create_ui()
    
    def setup_window(self):
        """Configure window settings"""
        self.window.title("Password Strength Analyzer")
        self.window.geometry("600x650")
        self.window.configure(bg=BG_COLOR)
        self.window.resizable(False, False)
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_ui(self):
        """Create UI components"""
        # Header
        frame_header = Frame(self.window, bg=BG_COLOR, pady=20)
        frame_header.pack(fill="x")
        
        Label(frame_header, text="PASSECURIST", 
              font=("Segoe UI", 22, "bold"), fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        Label(frame_header, text="Password Strength Analyzer", 
              font=("Segoe UI", 10), fg=TEXT_MAIN, bg=BG_COLOR).pack()
        
        # Input area
        frame_input = Frame(self.window, bg=CARD_COLOR, padx=30, pady=25)
        frame_input.pack(fill="x", pady=10, padx=20)
        
        Label(frame_input, text="Enter Password:", 
              font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        
        self.entry_pass = Entry(frame_input, font=("Consolas", 13),
                               bg="#334155", fg="white", insertbackground="white", relief="flat")
        self.entry_pass.pack(pady=12, ipady=6, fill="x")
        
        btn_check = Button(frame_input, text="ANALYZE PASSWORD STRENGTH",
                          command=self.check_password,
                          bg=ACCENT_COLOR, fg=BG_COLOR,
                          font=("Segoe UI", 10, "bold"),
                          relief="flat", cursor="hand2")
        btn_check.pack(fill="x", pady=8)
        
        # Enter key binding
        self.entry_pass.bind("<Return>", lambda e: self.check_password())
        self.entry_pass.focus_set()
        
        # Result area
        frame_result = Frame(self.window, bg=BG_COLOR, padx=20, pady=20)
        frame_result.pack(fill="both", expand=True)
        
        self.label_rating = Label(frame_result, text="VERDICT: WAITING...",
                                 font=("Segoe UI", 16, "bold"),
                                 fg="#64748b", bg=BG_COLOR)
        self.label_rating.pack(pady=(0, 15))

        # Strength bar using Canvas
        from tkinter import Canvas
        self.bar_canvas = Canvas(frame_result, height=30, bg=CARD_COLOR, 
                                highlightthickness=0)
        self.bar_canvas.pack(fill="x", pady=(0, 10))
        
        # Create the bar rectangle (starts at 0 width)
        self.bar_rect = self.bar_canvas.create_rectangle(
            0, 0, 0, 30, fill="#64748b", outline=""
)

        # Separator
        Frame(frame_result, height=2, bg=CARD_COLOR).pack(fill="x", pady=10)
        
        self.label_details = Label(frame_result, text="Enter a password to begin analysis.",
                                   font=("Segoe UI", 10), fg="#94a3b8", bg=BG_COLOR,
                                   justify="left", wraplength=420)
        self.label_details.pack(anchor="w", pady=10)
        
        # Back button
        btn_back = Button(self.window, text="BACK TO MENU", command=self.on_close,
                         font=("Segoe UI", 10), bg=CARD_COLOR, fg=TEXT_MAIN,
                         relief="flat", cursor="hand2")
        btn_back.pack(pady=20, padx=20, fill="x")
    
    def check_password(self):
        """Analyze password strength"""
        password = self.entry_pass.get().strip()
        
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password")
            return
        
        rating, color, messages = evaluate_password_strength(password)
        
        # Update verdict label
        self.label_rating.config(text=f"VERDICT: {rating}", fg=color)
        
        # Update strength bar
        bar_width = self.bar_canvas.winfo_width()
        
        # Calculate fill percentage based on rating
        if rating == "WEAK":
            fill_percent = 0.33
        elif rating == "MODERATE":
            fill_percent = 0.66
        else:  # STRONG
            fill_percent = 1.0
        
        # Update bar rectangle coordinates and color
        fill_width = bar_width * fill_percent
        self.bar_canvas.coords(self.bar_rect, 0, 0, fill_width, 30)
        self.bar_canvas.itemconfig(self.bar_rect, fill=color)
        
        # Update details
        details_text = "\n".join(f"• {msg}" for msg in messages) if messages else "No issues found."
        self.label_details.config(text=details_text)
    
    def on_close(self):
        """Returns you to main menu"""
        self.window.destroy()
        self.main_window.deiconify()