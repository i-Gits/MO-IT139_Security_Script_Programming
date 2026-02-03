# gui/styles.py
import tkinter.ttk as ttk
class AppTheme:
    BG = "#0f172a"
    CARD = "#1e293b"
    TEXT = "#e2e8f0"
    ACCENT = "#38bdf8"
    ACCENT_HOVER = "#0ea5e9"
    WEAK = "#ef4444"
    MOD = "#f59e0b"
    STRONG = "#22c55e"

    @staticmethod
    def apply(root):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure("TNotebook", background=AppTheme.BG, borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=AppTheme.CARD,
                        foreground="#94a3b8",
                        padding=[14, 10],
                        font=("Segoe UI", 11, "bold"))

        style.map("TNotebook.Tab",
                  background=[("selected", AppTheme.ACCENT),
                              ("active !selected", AppTheme.ACCENT_HOVER)],
                  foreground=[("selected", AppTheme.BG),
                              ("active !selected", AppTheme.BG)])

        style.configure("TNotebook.Tab", focuscolor="none")

        root.configure(bg=AppTheme.BG)