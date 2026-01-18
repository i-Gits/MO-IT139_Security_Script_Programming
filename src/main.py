# Entry point for the Password Security Toolkit (HW #1 & 2)

import tkinter as tk
from gui.main_menu import MainMenu

def main():
    """Launch the Password Security Toolkit"""
    root = tk.Tk()
    root.title("Password Security Toolkit")
    root.geometry("600x500")
    root.configure(bg="#0f172a")
    root.resizable(False, False)
    
    # Create and display main menu
    MainMenu(root)
    
    root.mainloop()

if __name__ == "__main__":
    main()