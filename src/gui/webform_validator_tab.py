# gui/web_validator_tab.py
import re
import tkinter as tk
from tkinter import ttk, messagebox, Frame, Label, Button, Text, Scrollbar, Entry, END
from features.webform_validator import validate_and_sanitize_form
from utils.security_logger import log_validation_summary, log_threat, log_attack_attempt

# Theme colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TEXT_MAIN = "#e2e8f0"
ACCENT_COLOR = "#38bdf8"
BTN_HOVER = "#0ea5e9"
INPUT_BG = "#334155"
SUCCESS_COLOR = "#22c55e"
ERROR_COLOR = "#ef4444"
WARNING_COLOR = "#f59e0b"
DETAIL_COLOR = "#94a3b8"


class WebValidatorTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_COLOR)
        self.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        tk.Label(self, text="PASSECURIST", font=("Segoe UI", 22, "bold"),
                 fg=ACCENT_COLOR, bg=BG_COLOR).pack(pady=(10, 5))

        tk.Label(self, text="Web Form Validator & Sanitizer",
                 font=("Segoe UI", 11), fg=TEXT_MAIN, bg=BG_COLOR).pack(pady=(0, 12))

        # Form card
        form_frame = tk.Frame(self, bg=CARD_COLOR, padx=30, pady=25)
        form_frame.pack(fill="x", pady=8)

        tk.Label(form_frame, text="Fill in the form fields to validate",
                 font=("Segoe UI", 13, "bold"), fg=ACCENT_COLOR, bg=CARD_COLOR).pack(anchor="w", pady=(0, 15))

        # Full Name
        tk.Label(form_frame, text="Full Name *", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        self.entry_name = tk.Entry(form_frame, font=("Consolas", 12),
                                   bg="#334155", fg=TEXT_MAIN,
                                   insertbackground="white", relief="flat")
        self.entry_name.pack(fill="x", pady=(4, 4), ipady=6)
        self.label_name_error = tk.Label(form_frame, text="", font=("Segoe UI", 9),
                                         fg=ERROR_COLOR, bg=CARD_COLOR, anchor="w")
        self.label_name_error.pack(fill="x", pady=(0, 12))

        # Email
        tk.Label(form_frame, text="Email Address *", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        self.entry_email = tk.Entry(form_frame, font=("Consolas", 12),
                                    bg="#334155", fg=TEXT_MAIN,
                                    insertbackground="white", relief="flat")
        self.entry_email.pack(fill="x", pady=(4, 4), ipady=6)
        self.label_email_error = tk.Label(form_frame, text="", font=("Segoe UI", 9),
                                          fg=ERROR_COLOR, bg=CARD_COLOR, anchor="w")
        self.label_email_error.pack(fill="x", pady=(0, 12))

        # Username
        tk.Label(form_frame, text="Username *", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        self.entry_username = tk.Entry(form_frame, font=("Consolas", 12),
                                       bg="#334155", fg=TEXT_MAIN,
                                       insertbackground="white", relief="flat")
        self.entry_username.pack(fill="x", pady=(4, 4), ipady=6)
        self.label_username_error = tk.Label(form_frame, text="", font=("Segoe UI", 9),
                                             fg=ERROR_COLOR, bg=CARD_COLOR, anchor="w")
        self.label_username_error.pack(fill="x", pady=(0, 12))

        # Message with conditional scrollbar
        tk.Label(form_frame, text="Message / Comment *", font=("Segoe UI", 11),
                 fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")
        
        msg_container = tk.Frame(form_frame, bg=CARD_COLOR)
        msg_container.pack(fill="x", pady=(4, 4))
        
        self.msg_scroll = Scrollbar(msg_container)
        
        self.text_message = tk.Text(msg_container, height=5, font=("Consolas", 12),
                                    bg="#334155", fg=TEXT_MAIN,
                                    insertbackground="white", wrap="word", relief="flat",
                                    yscrollcommand=self._on_message_scroll)
        self.text_message.pack(side="left", fill="both", expand=True)
        self.msg_scroll.config(command=self.text_message.yview)
        
        self.label_message_error = tk.Label(form_frame, text="", font=("Segoe UI", 9),
                                            fg=ERROR_COLOR, bg=CARD_COLOR, anchor="w")
        self.label_message_error.pack(fill="x", pady=(0, 16))

        # Buttons
        btn_frame = tk.Frame(form_frame, bg=CARD_COLOR)
        btn_frame.pack(fill="x", pady=(10, 0))

        tk.Button(btn_frame, text="VALIDATE FORM",
                  command=self.validate_form,
                  bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 11, "bold"),
                  relief="flat", activebackground=BTN_HOVER, cursor="hand2").pack(side="left", fill="x", expand=True, padx=(0, 10))

        tk.Button(btn_frame, text="CLEAR ALL",
                  command=self.clear_form,
                  bg="#475569", fg=TEXT_MAIN, font=("Segoe UI", 11, "bold"),
                  relief="flat", activebackground="#334155", cursor="hand2").pack(side="left")

        tk.Label(form_frame, text="* All fields are required", 
                 font=("Segoe UI", 9, "italic"), fg="#64748b", bg=CARD_COLOR).pack(anchor="center", pady=(15, 0))

        # Status indicator card (initially hidden)
        self.status_frame = tk.Frame(self, bg=CARD_COLOR, padx=30, pady=20)
        self.status_label = tk.Label(self.status_frame, text="", font=("Segoe UI", 12, "bold"),
                                     fg=TEXT_MAIN, bg=CARD_COLOR, justify="left", anchor="w")
        self.status_label.pack(fill="x")

    def _on_message_scroll(self, *args):
        """Show/hide message scrollbar based on content"""
        self.msg_scroll.set(*args)
        if float(args[0]) > 0.0 or float(args[1]) < 1.0:
            self.msg_scroll.pack(side="right", fill="y")
        else:
            self.msg_scroll.pack_forget()

    def clear_errors(self):
        """Clear all error messages"""
        self.label_name_error.config(text="")
        self.label_email_error.config(text="")
        self.label_username_error.config(text="")
        self.label_message_error.config(text="")
        self.status_frame.pack_forget()

    def validate_form(self):
        """Validate form and show inline errors (user-facing only)"""
        self.clear_errors()
        
        form_data = {
            'full_name': self.entry_name.get(),
            'email': self.entry_email.get(),
            'username': self.entry_username.get(),
            'message': self.text_message.get("1.0", END).strip()
        }
        
        # Call backend validation and sanitization
        results = validate_and_sanitize_form(form_data)
        
        # Log validation summary to file (backend logging - not shown to user)
        log_validation_summary(form_data, results)
        
        # Check for empty fields
        if results.get('has_empty_fields'):
            empty_list = ', '.join(results['empty_fields'])
            messagebox.showerror(
                "Required Fields Missing",
                f"Please fill in all required fields:\n\n{empty_list}"
            )
            return
        
        # Track if any errors found
        has_errors = False
        

        # FULL NAME VALIDATION - Show user-facing errors only
        name_errors = self.get_all_name_errors(form_data['full_name'])
        if name_errors:
            self.label_name_error.config(text=f"✗ {' • '.join(name_errors)}", fg=ERROR_COLOR)
            has_errors = True
            
            # Log suspicious full name attempts (contains numbers or excessive invalid chars)
            if 'Cannot contain numbers' in ' '.join(name_errors) or 'Contains invalid characters' in ' '.join(name_errors):
                from utils.security_logger import log_sanitization
                sanitized = results['sanitized']['full_name']
                log_sanitization('Full Name', form_data['full_name'], sanitized, 
                               f"Invalid input rejected: {', '.join(name_errors[:2])}")
        else:
            self.label_name_error.config(text="✓ Valid", fg=SUCCESS_COLOR)
            # Log sanitization to file if it occurred (backend only)
            if results['validation']['full_name']['sanitized']:
                original = form_data['full_name']
                sanitized = results['sanitized']['full_name']
                # Silent logging - user doesn't see this
                from utils.security_logger import log_sanitization
                log_sanitization('Full Name', original, sanitized, 'Invalid characters removed and formatted')
        

        # EMAIL VALIDATION - Show user-facing errors only
        email_errors = self.get_all_email_errors(form_data['email'])
        if email_errors:
            self.label_email_error.config(text=f"✗ {' • '.join(email_errors)}", fg=ERROR_COLOR)
            has_errors = True
            
            # Log disposable email attempts to file
            if 'Disposable email not allowed' in ' '.join(email_errors):
                log_attack_attempt('Email', 'DISPOSABLE EMAIL ATTEMPT', form_data['email'])
        else:
            self.label_email_error.config(text="✓ Valid", fg=SUCCESS_COLOR)
            # Log sanitization to file if it occurred (backend only)
            if results['validation']['email']['sanitized']:
                original = form_data['email']
                sanitized = results['sanitized']['email']
                from utils.security_logger import log_sanitization
                log_sanitization('Email', original, sanitized, 'Normalized to standard format')
        

        # USERNAME VALIDATION - Show user-facing errors only
        username_errors = self.get_all_username_errors(form_data['username'])
        if username_errors:
            self.label_username_error.config(text=f"✗ {' • '.join(username_errors)}", fg=ERROR_COLOR)
            has_errors = True
            
            # Log suspicious username attempts (invalid characters, length issues)
            if 'Invalid characters' in ' '.join(username_errors) or 'Cannot start with a number' in ' '.join(username_errors):
                from utils.security_logger import log_sanitization
                sanitized = results['sanitized']['username']
                log_sanitization('Username', form_data['username'], sanitized,
                               f"Invalid input rejected: {', '.join(username_errors[:2])}")
        else:
            self.label_username_error.config(text="✓ Valid", fg=SUCCESS_COLOR)
            # Log sanitization to file if it occurred (backend only)
            if results['validation']['username']['sanitized']:
                original = form_data['username']
                sanitized = results['sanitized']['username']
                from utils.security_logger import log_sanitization
                log_sanitization('Username', original, sanitized, 'Invalid characters removed')
        

        # MESSAGE VALIDATION - Show user-facing errors only
        message_errors = self.get_all_message_errors(form_data['message'])
        if message_errors:
            self.label_message_error.config(text=f"✗ {' • '.join(message_errors)}", fg=ERROR_COLOR)
            has_errors = True
            
            # Log security threats to file (XSS, SQL injection attempts)
            threats = results['validation']['message'].get('threats', [])
            if threats:
                # Determine attack type
                message_upper = form_data['message'].upper()
                if any(kw in message_upper for kw in ['SELECT', 'DROP', 'INSERT', 'DELETE', 'UPDATE']):
                    log_attack_attempt('Message', 'SQL INJECTION ATTEMPT', form_data['message'])
                elif '<script' in form_data['message'].lower() or 'javascript:' in form_data['message'].lower():
                    log_attack_attempt('Message', 'XSS ATTEMPT', form_data['message'])
                else:
                    log_attack_attempt('Message', 'MALICIOUS CONTENT', form_data['message'])
        else:
            self.label_message_error.config(text="✓ Valid", fg=SUCCESS_COLOR)
            # Log sanitization to file if it occurred (backend only)
            if results['validation']['message']['sanitized']:
                original = form_data['message']
                sanitized = results['sanitized']['message']
                sanitization_notes = results.get('sanitization_notes', [])
                log_threat('Message', 'CONTENT SANITIZED', original, sanitized, sanitization_notes)
        

        # OVERALL STATUS INDICATOR - Simple user-facing message (to not overwhelm users & not give too much info)
        if has_errors:
            self.show_status_indicator("✗ Validation Failed", 
                                      "Please correct the errors above and try again.", 
                                      ERROR_COLOR)
        else:
            self.show_status_indicator("✓ All Fields Valid", 
                                      "Your form submission is clean and ready!", 
                                      SUCCESS_COLOR)
    
    def get_all_name_errors(self, name):
        """Get all validation errors for full name"""
        errors = []
        
        if not name or len(name.strip()) < 1:
            errors.append("Field is required")
            return errors
        
        if len(name.strip()) < 2:
            errors.append("Must be at least 2 characters")
        
        if re.search(r'\d', name):
            errors.append("Cannot contain numbers")
        
        invalid_chars = set(re.findall(r'[^a-zA-Z\s\'\-]', name))
        if invalid_chars:
            char_display = ', '.join(f"'{c}'" for c in sorted(invalid_chars))
            errors.append(f"Contains invalid characters: {char_display}")
        
        if re.search(r'\s{2,}', name):
            errors.append("Too many consecutive spaces")
        
        return errors
    
    def get_all_email_errors(self, email):
        """Get all validation errors for email"""
        errors = []
        
        if not email or not email.strip():
            errors.append("Field is required")
            return errors
        
        email = email.strip()
        
        if len(email) > 320:
            errors.append("Too long (max 320 characters)")
        
        if len(email) < 6:
            errors.append("Too short (min 6 characters)")
        
        if ' ' in email:
            errors.append("Cannot contain spaces")
        
        if '@' not in email:
            errors.append("Missing '@' symbol")
        elif email.count('@') > 1:
            errors.append("Multiple '@' symbols not allowed")
        else:
            try:
                local_part, domain_part = email.rsplit('@', 1)
                
                if not local_part:
                    errors.append("Missing local part (before @)")
                else:
                    if len(local_part) > 64:
                        errors.append("Local part too long (max 64 chars)")
                    
                    if not local_part[0].isalnum():
                        errors.append("Cannot start with special character")
                    
                    if not local_part[-1].isalnum():
                        errors.append("Cannot end with special character before @")
                    
                    if re.search(r'\.{2,}', local_part):
                        errors.append("Consecutive dots not allowed")
                    
                    if not re.match(r'^[a-zA-Z0-9._+-]+$', local_part):
                        errors.append("Invalid characters in local part")
                
                if not domain_part:
                    errors.append("Missing domain part (after @)")
                else:
                    if '.' not in domain_part:
                        errors.append("Missing domain extension (e.g., .com)")
                    
                    if '..' in domain_part:
                        errors.append("Consecutive dots in domain")
                    
                    if domain_part[0] in '.-':
                        errors.append("Domain starts with invalid character")
                    
                    if domain_part[-1] in '.-':
                        errors.append("Domain ends with invalid character")
                    
                    if '.' in domain_part:
                        tld = domain_part.split('.')[-1]
                        if len(tld) < 2:
                            errors.append("Invalid TLD (too short)")
                        if not tld.isalpha():
                            errors.append("TLD must contain only letters")
                    

                    # Check for disposable/temporary email domains
                    DISPOSABLE_DOMAINS = [
                        'temp-mail.org', 'guerrillamail.com', '10minutemail.com',
                        'mailinator.com', 'yopmail.com', 'trashmail.com', 'throwaway.email'
                    ]
                    
                    domain_lower = domain_part.lower()
                    for disposable in DISPOSABLE_DOMAINS:
                        if domain_lower.endswith(disposable):
                            errors.append(f"Disposable email not allowed ({disposable})")
                            break
                    
            except ValueError:
                errors.append("Invalid email structure")
        
        return errors
    
    def get_all_username_errors(self, username):
        """Get all validation errors for username"""
        errors = []
        
        if not username or not username.strip():
            errors.append("Field is required")
            return errors
        
        original_username = username
        username = username.strip()
        
        if len(username) < 4:
            errors.append("Must be at least 4 characters")
        
        if len(username) > 16:
            errors.append("Cannot exceed 16 characters")
        
        if username and username[0].isdigit():
            errors.append("Cannot start with a number")

        if ' ' in original_username:
            errors.append("Spaces are not allowed")

        if '__' in username:
            errors.append("Consecutive underscores not allowed")

        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', username):
            if username and not username[0].isalpha():
                if "Cannot start with a number" not in ' '.join(errors):
                    errors.append("Must start with a letter")
            
            invalid_chars = set(re.findall(r'[^a-zA-Z0-9_\s]', username))
            if invalid_chars:
                char_display = ', '.join(f"'{c}'" for c in sorted(invalid_chars))
                errors.append(f"Invalid characters: {char_display}")
        
        return errors
    
    def get_all_message_errors(self, message):
        """Get all validation errors for message"""
        errors = []
        
        if not message or not message.strip():
            errors.append("Field is required")
            return errors
        
        if len(message) > 250:
            errors.append(f"Too long ({len(message)}/250 characters)")
        
        message_upper = message.upper()
        
        sql_keywords = ["SELECT", "DROP", "INSERT", "DELETE", "UPDATE", "UNION",
                       "CREATE", "ALTER", "EXEC", "EXECUTE", "OR 1=1", "OR '1'='1"]
        sql_found = []
        for keyword in sql_keywords:
            if keyword in message_upper:
                sql_found.append(keyword)
        
        if sql_found:
            errors.append(f"SQL keywords detected: {', '.join(sql_found[:3])}")
        
        if '<script' in message.lower():
            errors.append("Script tags not allowed")
        
        if '<iframe' in message.lower():
            errors.append("Iframe tags not allowed")
        
        if '<img' in message.lower() and ('onerror' in message.lower() or 'onclick' in message.lower()):
            errors.append("Suspicious image tags detected")
        
        if 'javascript:' in message.lower():
            errors.append("JavaScript protocol not allowed")
        
        if re.search(r'on\w+\s*=', message, re.IGNORECASE):
            errors.append("Event handlers not allowed")
        
        return errors

    def show_status_indicator(self, title, message, color):
        """Show overall validation status at the bottom"""
        self.status_label.config(text=f"{title}\n{message}", fg=color)
        self.status_frame.pack(fill="x", pady=(8, 0))

    def clear_form(self):
        """Clear all form fields and errors"""
        self.entry_name.delete(0, END)
        self.entry_email.delete(0, END)
        self.entry_username.delete(0, END)
        self.text_message.delete("1.0", END)
        self.clear_errors()
        messagebox.showinfo("Form Cleared", "All fields have been cleared.")