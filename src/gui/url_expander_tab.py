# Run this code to create simple url expander GUI 


import tkinter as tk
from tkinter import messagebox
import requests

def expand_url(short_url):
    try:
        # Send a HEAD request (faster, no content download)
        response = requests.head(short_url, allow_redirects=True, timeout=10)
        return response.url
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

def on_expand():
    short_url = entry.get().strip()
    if not short_url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return
    
    result = expand_url(short_url)
    output_var.set(result)

# Create main window
root = tk.Tk()
root.title("URL Expander")

# Input field
tk.Label(root, text="Enter shortened URL:").pack(pady=5)
entry = tk.Entry(root, width=50)
entry.pack(pady=5)

# Expand button
tk.Button(root, text="Expand URL", command=on_expand).pack(pady=10)

# Output field
output_var = tk.StringVar()
tk.Label(root, text="Expanded URL:").pack(pady=5)
tk.Entry(root, textvariable=output_var, width=50, state="readonly").pack(pady=5)

root.mainloop()