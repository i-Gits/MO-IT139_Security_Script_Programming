# src/main.py
import tkinter as tk
from tkinter import ttk

from gui.password_strength_tab import PasswordStrengthTab

def main():
    root = tk.Tk()
    root.title("PASSECURIST - Security Toolkit")
    root.geometry("580x650")
    root.configure(bg="#0f172a")

    # Simple notebook with minimal styling
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    # Password Strength tab 
    tab_strength = tk.Frame(notebook, bg="#0f172a")
    notebook.add(tab_strength, text="Password Strength")

    PasswordStrengthTab(tab_strength)

    root.mainloop()


if __name__ == "__main__":
    main()