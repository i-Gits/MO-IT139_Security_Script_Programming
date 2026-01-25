# Web form validator/sanitizer window with detailed error messages


import tkinter as tk
from tkinter import Frame, Label, Entry, Button, Text, Scrollbar, END, Toplevel, messagebox
from features.webform_validator_sanitizer import validate_and_sanitize_form

# Theme colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
INPUT_BG = "#334155"
SUCCESS_COLOR = "#22c55e"
ERROR_COLOR = "#ef4444"
WARNING_COLOR = "#f59e0b"
DETAIL_COLOR = "#94a3b8"


class FormValidatorWindow:
    """Web form input validator and sanitizer window"""
    
    def __init__(self, main_window):
        self.main_window = main_window
        self.window = tk.Toplevel()
        self.setup_window()
        self.create_ui()
    
    def setup_window(self):
        """Configure window settings - same size as other tools"""
        self.window.title("Web Form Validator & Sanitizer")
        self.window.geometry("600x730")  # Increased height for clear button
        self.window.configure(bg=BG_COLOR)
        self.window.resizable(False, False)
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_ui(self):
        """Create UI components"""
        # Header
        frame_header = Frame(self.window, bg=BG_COLOR, pady=15)
        frame_header.pack()
        
        Label(frame_header, text="WEB FORM VALIDATOR", 
              font=("Segoe UI", 20, "bold"), fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        Label(frame_header, text="Validate and Sanitize User Input for Security", 
              font=("Segoe UI", 10), fg=TEXT_MAIN, bg=BG_COLOR).pack()
        
        # Input form area
        frame_form = Frame(self.window, bg=CARD_COLOR, padx=30, pady=25)
        frame_form.pack(fill="x", pady=10, padx=20)
        
        # Full Name field
        Label(frame_form, text="Full Name: *", 
              font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_COLOR).grid(
              row=0, column=0, sticky="w", pady=(0, 5))
        self.entry_name = Entry(frame_form, font=("Consolas", 13),
                               bg="#334155", fg="white", insertbackground="white", relief="flat")
        self.entry_name.grid(row=1, column=0, pady=(0, 15), ipady=6, sticky="ew")
        
        # Email field
        Label(frame_form, text="Email Address: *", 
              font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_COLOR).grid(
              row=2, column=0, sticky="w", pady=(0, 5))
        self.entry_email = Entry(frame_form, font=("Consolas", 13),
                                bg="#334155", fg="white", insertbackground="white", relief="flat")
        self.entry_email.grid(row=3, column=0, pady=(0, 15), ipady=6, sticky="ew")
        
        # Username field
        Label(frame_form, text="Username: *", 
              font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_COLOR).grid(
              row=4, column=0, sticky="w", pady=(0, 5))
        self.entry_username = Entry(frame_form, font=("Consolas", 13),
                                    bg="#334155", fg="white", insertbackground="white", relief="flat")
        self.entry_username.grid(row=5, column=0, pady=(0, 15), ipady=6, sticky="ew")
        
        # Message field
        Label(frame_form, text="Message / Comment: *", 
              font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_COLOR).grid(
              row=6, column=0, sticky="w", pady=(0, 5))
        self.text_message = Text(frame_form, font=("Consolas", 11), height=4,
                                bg="#334155", fg="white", insertbackground="white", 
                                relief="flat", wrap="word")
        self.text_message.grid(row=7, column=0, pady=(0, 15), sticky="ew")
        
        frame_form.grid_columnconfigure(0, weight=1)
        
        # Validate button
        btn_validate = Button(frame_form, text="VALIDATE & SANITIZE FORM",
                             command=self.validate_form,
                             font=("Segoe UI", 11, "bold"), bg=ACCENT_COLOR, fg=BG_COLOR,
                             relief="flat", cursor="hand2")
        btn_validate.grid(row=8, column=0, pady=(10, 0), sticky="ew", ipady=4)
        
        # Clear button
        btn_clear = Button(frame_form, text="CLEAR FORM",
                          command=self.clear_form,
                          font=("Segoe UI", 9), bg=ERROR_COLOR, fg="white",
                          relief="flat", cursor="hand2")
        btn_clear.grid(row=9, column=0, pady=(10, 0), sticky="ew", ipady=4)
        
        # Required fields note
        note_frame = Frame(self.window, bg=BG_COLOR, pady=8)
        note_frame.pack(fill="x")
        
        Label(note_frame, text="* All fields are required", 
              font=("Segoe UI", 9, "italic"), fg="#64748b", bg=BG_COLOR).pack()
               
        # Back to menu button
        btn_frame = Frame(self.window, bg=BG_COLOR, pady=10)
        btn_frame.pack(fill="x", padx=20)
        
        btn_menu = Button(btn_frame, text="BACK TO MENU", 
                         command=self.on_close,
                         font=("Segoe UI", 10), bg=CARD_COLOR, fg=TEXT_MAIN,
                         relief="flat", cursor="hand2")
        btn_menu.pack(fill="x", ipady=4)
    
    def validate_form(self):
        """Validate and sanitize form data with empty field check"""
        # Collect form data (using dictionary as per requirements)
        form_data = {
            'full_name': self.entry_name.get(),
            'email': self.entry_email.get(),
            'username': self.entry_username.get(),
            'message': self.text_message.get("1.0", END).strip()
        }
        
        # Validate and sanitize
        results = validate_and_sanitize_form(form_data)
        
        # Check for empty fields
        if results.get('has_empty_fields'):
            empty_list = ', '.join(results['empty_fields'])
            messagebox.showerror(
                "Required Fields Missing",
                f"Please fill in all required fields:\n\n{empty_list}\n\n* All fields are required"
            )
            return
        
        # Show results in pop-up window
        self.show_results_popup(results)
    
    def show_results_popup(self, results):
        """Display validation results in pop-up with detailed error messages"""
        # Create pop-up window
        popup = Toplevel(self.window)
        popup.title("Validation & Sanitization Results")
        popup.geometry("800x700")
        popup.configure(bg=BG_COLOR)
        popup.resizable(False, False)
        
        # Header
        header_frame = Frame(popup, bg=BG_COLOR, pady=15)
        header_frame.pack()
        
        Label(header_frame, text="VALIDATION RESULTS", 
              font=("Segoe UI", 18, "bold"), fg=ACCENT_COLOR, bg=BG_COLOR).pack()
        Label(header_frame, text="Detailed analysis of your form submission", 
              font=("Segoe UI", 10), fg=TEXT_MAIN, bg=BG_COLOR).pack()
        
        # Results display area
        results_frame = Frame(popup, bg=BG_COLOR, padx=20)
        results_frame.pack(fill="both", expand=True, pady=10)
        
        # Scrollable text area
        scroll_frame = Frame(results_frame, bg=CARD_COLOR)
        scroll_frame.pack(fill="both", expand=True)
        
        scrollbar = Scrollbar(scroll_frame)
        scrollbar.pack(side="right", fill="y")
        
        results_text = Text(scroll_frame, height=28, width=90,
                           yscrollcommand=scrollbar.set, font=("Consolas", 10),
                           bg=CARD_COLOR, fg=TEXT_MAIN, relief="flat", wrap="word")
        results_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.config(command=results_text.yview)
        
        # Populate results with detailed error messages
        self.populate_results_text(results_text, results)
        
        # Configure text tags
        results_text.tag_config("info", foreground=TEXT_MAIN)
        results_text.tag_config("header", foreground=ACCENT_COLOR, 
                               font=("Segoe UI", 12, "bold"))
        results_text.tag_config("success", foreground=SUCCESS_COLOR, 
                               font=("Consolas", 11, "bold"))
        results_text.tag_config("error", foreground=ERROR_COLOR, 
                               font=("Consolas", 11, "bold"))
        results_text.tag_config("warning", foreground=WARNING_COLOR, 
                               font=("Consolas", 10, "bold"))
        results_text.tag_config("detail", foreground=DETAIL_COLOR, 
                               font=("Consolas", 9, "italic"))
        results_text.tag_config("section", foreground=ACCENT_COLOR, 
                               font=("Segoe UI", 11, "bold"))
        results_text.tag_config("threat", foreground=ERROR_COLOR, 
                               font=("Consolas", 9))
        
        # Make text read-only
        results_text.config(state="disabled")
        
        # Button frame
        btn_frame = Frame(popup, bg=BG_COLOR, pady=10)
        btn_frame.pack(fill="x", padx=20)
        
        # Close button
        btn_close = Button(btn_frame, text="CLOSE", command=popup.destroy,
                          font=("Segoe UI", 10, "bold"), bg=ACCENT_COLOR, fg=BG_COLOR,
                          relief="flat", cursor="hand2")
        btn_close.pack(side="left", fill="x", expand=True, padx=(0, 5), ipady=4)
        
    
    def populate_results_text(self, text_widget, results):
        """Populate results with detailed error messages for each field"""
        # Header
        text_widget.insert(END, "=" * 85 + "\n", "info")
        text_widget.insert(END, "FIELD-BY-FIELD VALIDATION RESULTS\n", "section")
        text_widget.insert(END, "=" * 85 + "\n\n", "info")
        
        # Validation details for each field
        field_names = [
            ('Full Name', 'full_name'),
            ('Email Address', 'email'),
            ('Username', 'username'),
            ('Message', 'message')
        ]
        
        for display_name, field_key in field_names:
            validation = results['validation'][field_key]
            
            # Field header
            text_widget.insert(END, f"━━━ {display_name.upper()} ━━━\n", "section")
            
            # Validation status
            if validation['valid']:
                text_widget.insert(END, f"Status: ✓ VALID\n", "success")
            else:
                text_widget.insert(END, f"Status: ✗ INVALID\n", "error")
                text_widget.insert(END, f"Error: {validation['message']}\n", "error")
                
                # Show detailed error information
                if validation.get('details'):
                    text_widget.insert(END, f"Details: {validation['details']}\n", "detail")
                
                # Show threats for message field
                if field_key == 'message' and validation.get('threats'):
                    text_widget.insert(END, "\nSecurity Threats Detected:\n", "warning")
                    for threat in validation['threats']:
                        text_widget.insert(END, f"  ⚠ {threat}\n", "threat")
            
            # Show sanitization info
            if validation.get('sanitized'):
                text_widget.insert(END, "\n Field was sanitized during processing\n", "warning")
            
            text_widget.insert(END, "\n")
        
        # Sanitized Output Section
        text_widget.insert(END, "=" * 85 + "\n", "info")
        text_widget.insert(END, "SANITIZED OUTPUT (SAFE FOR DATABASE)\n", "section")
        text_widget.insert(END, "=" * 85 + "\n\n", "info")
        
        text_widget.insert(END, f"Full Name:     {results['sanitized']['full_name']}\n", "info")
        text_widget.insert(END, f"Email:         {results['sanitized']['email']}\n", "info")
        text_widget.insert(END, f"Username:      {results['sanitized']['username']}\n", "info")
        text_widget.insert(END, f"Message:       {results['sanitized']['message']}\n\n", "info")
        
        # Error Summary (if any errors)
        if results.get('errors'):
            text_widget.insert(END, "=" * 85 + "\n", "info")
            text_widget.insert(END, "ERROR SUMMARY\n", "section")
            text_widget.insert(END, "=" * 85 + "\n\n", "info")
            
            for error in results['errors']:
                if error.startswith('  →'):
                    text_widget.insert(END, f"{error}\n", "detail")
                else:
                    text_widget.insert(END, f"{error}\n", "error")
            
            text_widget.insert(END, "\n")
        
        # Sanitization Summary (if any sanitization occurred)
        if results['summary']:
            text_widget.insert(END, "=" * 85 + "\n", "info")
            text_widget.insert(END, "SANITIZATION SUMMARY\n", "section")
            text_widget.insert(END, "=" * 85 + "\n\n", "info")
            
            text_widget.insert(END, 
                "The following fields were automatically sanitized for security:\n\n", "info")
            
            for item in results['summary']:
                text_widget.insert(END, f"• {item}\n", "warning")
            
            # Message-specific sanitization notes
            if results.get('sanitization_notes'):
                text_widget.insert(END, "\nMessage Sanitization Actions:\n", "warning")
                for note in results['sanitization_notes']:
                    text_widget.insert(END, f"  ⚙ {note}\n", "detail")
            
            text_widget.insert(END, "\n")
        
        # Final Status
        text_widget.insert(END, "=" * 85 + "\n", "info")
        text_widget.insert(END, "FINAL STATUS\n", "section")
        text_widget.insert(END, "=" * 85 + "\n\n", "info")
        
        if results['all_valid'] and not results['summary']:
            text_widget.insert(END, "✓ ALL FIELDS VALID - NO SANITIZATION REQUIRED\n", "success")
            text_widget.insert(END, "\nYour form submission is clean and ready for processing.\n", "info")
        elif results['all_valid']:
            text_widget.insert(END, "⚠ FORM VALID AFTER SANITIZATION\n", "warning")
            text_widget.insert(END, "\nAll fields passed validation after automatic sanitization.\n", "info")
            text_widget.insert(END, "Please review the sanitized output above before proceeding.\n", "info")
        else:
            text_widget.insert(END, "✗ VALIDATION FAILED\n", "error")
            text_widget.insert(END, "\nPlease correct the errors listed above and resubmit.\n", "info")
        
        text_widget.insert(END, "\n" + "=" * 85 + "\n", "info")
    
    def clear_form(self):
        """Clear all form fields"""
        self.entry_name.delete(0, END)
        self.entry_email.delete(0, END)
        self.entry_username.delete(0, END)
        self.text_message.delete("1.0", END)
        messagebox.showinfo("Form Cleared", "All fields have been cleared.")
    
    def on_close(self):
        """Handle window close - return to main menu"""
        self.window.destroy()
        self.main_window.deiconify()