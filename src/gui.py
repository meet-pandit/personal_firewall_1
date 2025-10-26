import json
import threading
import time
import tkinter as tk
from tkinter import ttk

from .logger_util import setup_logging
from .rules import load_rules
from .sniffer import FirewallSniffer


logger = setup_logging("gui")


class MonitorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Python Personal Firewall")
        self.text = tk.Text(root, height=20, width=90)
        self.text.pack(fill=tk.BOTH, expand=True)
        self.rule_label = ttk.Label(root, text="Rules loaded")
        self.rule_label.pack(anchor=tk.W)
        self.sniffer = None

    def start_sniffer(self):
        rules = load_rules()
        self.rule_label.config(text=f"Rules: {len(rules)} loaded")

        def log_handler(msg: str):
            self.text.insert(tk.END, msg + "\n")
            self.text.see(tk.END)

        # Monkey-patch logger to also show in GUI
        import logging

        class TkHandler(logging.Handler):
            def emit(self, record):
                try:
                    msg = self.format(record)
                    self.root.after(0, log_handler, msg)
                except Exception:
                    pass

        tk_handler = TkHandler()
        tk_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.root.addHandler(tk_handler)

        self.sniffer = FirewallSniffer(rules, iface=None)
        self.sniffer.start()

    def stop_sniffer(self):
        if self.sniffer:
            self.sniffer.stop()


def run_gui():
    root = tk.Tk()
    app = MonitorGUI(root)
    app.start_sniffer()
    def on_close():
        app.stop_sniffer()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    run_gui()


