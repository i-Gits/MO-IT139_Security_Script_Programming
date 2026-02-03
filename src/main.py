# src/main.py
import tkinter as tk
from tkinter import ttk

from gui.styles import AppTheme
from gui.password_strength_tab import PasswordStrengthTab
from gui.password_generator_tab import PasswordGeneratorTab
from gui.webform_validator_tab import WebValidatorTab


def main():
    root = tk.Tk()
    root.title("PASSECURIST - Security Toolkit")
    root.geometry("640x920")

    # App theme
    AppTheme.apply(root)

    # Notebook
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=12, pady=(10, 12))

    # Tab 1
    tab1 = tk.Frame(notebook, bg=AppTheme.BG)
    notebook.add(tab1, text="  Strength Checker  ")
    PasswordStrengthTab(tab1)

    # Tab 2
    tab2 = tk.Frame(notebook, bg=AppTheme.BG)
    notebook.add(tab2, text="  Generator & Hash  ")
    PasswordGeneratorTab(tab2)

    tab3 = tk.Frame(notebook, bg=AppTheme.BG)
    notebook.add(tab3, text="  Web Validator  ")
    WebValidatorTab(tab3)

    
    tk.Frame(root, height=2, bg=AppTheme.ACCENT).pack(fill="x", side="bottom")

    root.mainloop()


if __name__ == "__main__":
    main()