"""
pdu_manager_tk.py

Tkinter GUI PDU manager that opens an interactive SSH shell to PDUs and sends EXACT commands:
  device
  load <n>
  off force / on force / cycle force
  end

Features:
- Add / edit / remove devices (ip, username, password, name)
- Save devices to devices.json
- Connect / Disconnect per selected device
- Console shows live remote output and commands
- Auto-respond "yes" to common confirmation prompts
- Header: Spider-Man quote in red, Footer bottom-right: Ahmed Aldulaimi

Requirements:
  pip install paramiko

Run:
  python pdu_manager_tk.py
"""

import json
import threading
import queue
import time
import os
import sys
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext

try:
    import paramiko
except Exception as e:
    tk.messagebox.showerror("Missing dependency", "Paramiko is required. Run:\n\npip install paramiko")
    raise

DATA_FILE = "devices.json"
DEFAULT_DEVICES = [{"name": f"rack {i}", "ip": "", "username": "localadmin", "password": ""} for i in range(1, 9)]
READ_TIMEOUT = 0.3


# -------------------------
# Device persistence
# -------------------------
def load_devices():
    if Path(DATA_FILE).exists():
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                if isinstance(d, list):
                    return d
        except Exception:
            pass
    save_devices(DEFAULT_DEVICES)
    return DEFAULT_DEVICES.copy()


def save_devices(devs):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(devs, f, indent=2)


# -------------------------
# SSH interactive session
# -------------------------
class SSHInteractive:
    def __init__(self):
        self.client = None
        self.shell = None
        self.recv_q = queue.Queue()
        self.alive = False
        self._reader = None
        self._lock = threading.Lock()

    def connect(self, ip, username, password, port=22, timeout=8):
        self.close()
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # connect (raises on failure)
        self.client.connect(ip, port=port, username=username, password=password, timeout=timeout, look_for_keys=False, allow_agent=False)
        self.shell = self.client.invoke_shell()
        self.shell.settimeout(0.5)
        self.alive = True
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()

    def _reader_loop(self):
        try:
            while self.alive:
                try:
                    if self.shell.recv_ready():
                        data = self.shell.recv(4096)
                        if not data:
                            # closed
                            self.recv_q.put(("<CLOSED>", ""))
                            self.alive = False
                            break
                        text = data.decode(errors="ignore")
                        self.recv_q.put(("OUT", text))
                        # auto-detect yes/no prompts in received text and enqueue an auto-response
                        lower = text.lower()
                        if ("[y/n]" in lower) or ("(y/n)" in lower) or ("yes/no" in lower) or ("are you sure" in lower) or ("confirm" in lower):
                            # small delay then send yes
                            time.sleep(0.1)
                            try:
                                self.send("yes")
                                self.recv_q.put(("AUTO", "[Auto-sent 'yes']\n"))
                            except Exception as e:
                                self.recv_q.put(("ERR", f"[Auto-respond failed: {e}]\n"))
                    else:
                        time.sleep(READ_TIMEOUT)
                except Exception:
                    # continue reading until closed
                    time.sleep(READ_TIMEOUT)
        except Exception:
            self.recv_q.put(("ERR", traceback.format_exc()))
            self.alive = False

    def send(self, text):
        with self._lock:
            if not self.shell or not self.alive:
                raise RuntimeError("Not connected")
            if not text.endswith("\n"):
                text = text + "\n"
            self.shell.send(text)

    def get_now(self):
        out = []
        while True:
            try:
                out.append(self.recv_q.get_nowait())
            except queue.Empty:
                break
        return out

    def close(self):
        self.alive = False
        try:
            if self.shell:
                self.shell.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass


# -------------------------
# GUI
# -------------------------
class PDUManagerGUI:
    def __init__(self, master):
        self.master = master
        master.title("PDU Manager - Ahmed Aldulaimi")
        # Compact starting size but wide enough for controls
        master.geometry("920x540")
        master.minsize(820, 460)

        # Devices
        self.devices = load_devices()

        # Top header (Spider-Man quote)
        header = tk.Label(master, text='With great power comes great responsibility', fg="red", font=("Helvetica", 14, "bold"))
        header.pack(side=tk.TOP, fill=tk.X, pady=(6, 4))

        # Main frame (left devices / right console & controls)
        main = tk.Frame(master)
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Left panel
        left = tk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))

        tk.Label(left, text="PDUs").pack(anchor="w")
        self.device_listbox = tk.Listbox(left, width=30, height=20)
        self.device_listbox.pack(fill=tk.Y, expand=False)
        self.refresh_devices_listbox()

        btn_frame = tk.Frame(left)
        btn_frame.pack(fill=tk.X, pady=(6, 0))
        tk.Button(btn_frame, text="Add", width=8, command=self.add_device).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Edit", width=8, command=self.edit_device).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Remove", width=8, command=self.remove_device).pack(side=tk.LEFT, padx=2)

        conn_frame = tk.Frame(left)
        conn_frame.pack(fill=tk.X, pady=(8, 0))
        self.connect_btn = tk.Button(conn_frame, text="Connect", width=14, command=self.connect_to_selected)
        self.connect_btn.pack(side=tk.LEFT, padx=2)
        self.disconnect_btn = tk.Button(conn_frame, text="Disconnect", width=14, command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=2)

        self.status_label = tk.Label(left, text="Not connected", fg="blue")
        self.status_label.pack(anchor="w", pady=(8, 0))

        # Right panel
        right = tk.Frame(main)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Console
        console_label = tk.Label(right, text="Console")
        console_label.pack(anchor="w")
        self.console = scrolledtext.ScrolledText(right, wrap=tk.WORD, height=20)
        self.console.pack(fill=tk.BOTH, expand=True)
        self.console.configure(state=tk.DISABLED)

        # Controls under console
        control_frame = tk.Frame(right)
        control_frame.pack(fill=tk.X, pady=(6, 2))

        # Load entry and quick buttons
        tk.Label(control_frame, text="Load #:").pack(side=tk.LEFT)
        self.load_entry = tk.Entry(control_frame, width=6)
        self.load_entry.pack(side=tk.LEFT, padx=(4, 12))
        tk.Button(control_frame, text="Device", command=self.cmd_device).pack(side=tk.LEFT, padx=4)
        tk.Button(control_frame, text="Load", command=self.cmd_load).pack(side=tk.LEFT, padx=4)
        tk.Button(control_frame, text="End", command=self.cmd_end).pack(side=tk.LEFT, padx=12)

        # Force action buttons
        tk.Button(control_frame, text="Off Force", width=10, command=lambda: self.cmd_action("off force")).pack(side=tk.LEFT, padx=4)
        tk.Button(control_frame, text="On Force", width=10, command=lambda: self.cmd_action("on force")).pack(side=tk.LEFT, padx=4)
        tk.Button(control_frame, text="Cycle Force", width=10, command=lambda: self.cmd_action("cycle force")).pack(side=tk.LEFT, padx=4)

        # Bottom status / footer (bottom-right your name)
        footer = tk.Frame(master)
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=6, pady=(4, 6))
        self.footer_label = tk.Label(footer, text="")  # left empty to preserve spacing
        self.footer_label.pack(side=tk.LEFT, expand=True, anchor="w")
        name_label = tk.Label(footer, text="Ahmed Aldulaimi", anchor="e")
        name_label.pack(side=tk.RIGHT)

        # SSH session object
        self.session = SSHInteractive()

        # Start background loop to pull session output
        self.running = True
        self.bg_thread = threading.Thread(target=self._bg_loop, daemon=True)
        self.bg_thread.start()

        # Bind double-click on listbox to connect
        self.device_listbox.bind("<Double-Button-1>", lambda e: self.connect_to_selected())

    # -------------------------
    # device management
    # -------------------------
    def refresh_devices_listbox(self):
        self.device_listbox.delete(0, tk.END)
        for d in self.devices:
            n = d.get("name") or f"{d.get('ip')}"
            label = f"{n}  —  {d.get('ip')} ({d.get('username')})"
            self.device_listbox.insert(tk.END, label)

    def add_device(self):
        dlg = DeviceDialog(self.master, title="Add PDU")
        self.master.wait_window(dlg.top)
        if dlg.result:
            self.devices.append(dlg.result)
            save_devices(self.devices)
            self.refresh_devices_listbox()

    def edit_device(self):
        idxs = self.device_listbox.curselection()
        if not idxs:
            messagebox.showinfo("Edit", "Select a device first.")
            return
        idx = idxs[0]
        dlg = DeviceDialog(self.master, title="Edit PDU", initial=self.devices[idx])
        self.master.wait_window(dlg.top)
        if dlg.result:
            self.devices[idx] = dlg.result
            save_devices(self.devices)
            self.refresh_devices_listbox()

    def remove_device(self):
        idxs = self.device_listbox.curselection()
        if not idxs:
            messagebox.showinfo("Remove", "Select a device first.")
            return
        idx = idxs[0]
        if messagebox.askyesno("Remove", f"Remove {self.devices[idx].get('name')}?"):
            self.devices.pop(idx)
            save_devices(self.devices)
            self.refresh_devices_listbox()

    # -------------------------
    # connect / disconnect
    # -------------------------
    def connect_to_selected(self):
        idxs = self.device_listbox.curselection()
        if not idxs:
            messagebox.showinfo("Connect", "Select a device to connect.")
            return
        idx = idxs[0]
        dev = self.devices[idx]
        ip = dev.get("ip") or ""
        user = dev.get("username") or ""
        pw = dev.get("password") or ""
        if not ip or not user:
            messagebox.showwarning("Connect", "Device must have IP and username.")
            return

        self._append_console(f"\n[Connecting to {dev.get('name') or ip} ({ip})...]\n")
        self.connect_btn.configure(state=tk.DISABLED)
        # connect in background
        def _connect():
            try:
                self.session.connect(ip, user, pw)
                self._append_console(f"[Connected to {ip}]\n")
                self.status_label.configure(text=f"Connected: {ip}")
                self.connect_btn.configure(state=tk.DISABLED)
                self.disconnect_btn.configure(state=tk.NORMAL)
            except Exception as e:
                self._append_console(f"[Connection failed: {e}]\n")
                self.connect_btn.configure(state=tk.NORMAL)
                self.disconnect_btn.configure(state=tk.DISABLED)
        threading.Thread(target=_connect, daemon=True).start()

    def disconnect(self):
        try:
            self.session.close()
        finally:
            self._append_console("\n[Disconnected]\n")
            self.status_label.configure(text="Not connected")
            self.connect_btn.configure(state=tk.NORMAL)
            self.disconnect_btn.configure(state=tk.DISABLED)

    # -------------------------
    # Commands to remote
    # -------------------------
    def cmd_device(self):
        try:
            self.session.send("device")
            self._append_console("> device\n")
        except Exception as e:
            self._append_console(f"[Send failed: {e}]\n")

    def cmd_load(self):
        loadnum = self.load_entry.get().strip()
        if not loadnum:
            loadnum = simple_dialog_input(self.master, "Load number", "Enter load number (e.g., 12):")
            if not loadnum:
                return
        try:
            self.session.send(f"load {loadnum}")
            self._append_console(f"> load {loadnum}\n")
        except Exception as e:
            self._append_console(f"[Send failed: {e}]\n")

    def cmd_end(self):
        try:
            self.session.send("end")
            self._append_console("> end\n")
        except Exception as e:
            self._append_console(f"[Send failed: {e}]\n")

    def cmd_action(self, action_text):
        # action_text should be one of "off force", "on force", "cycle force"
        try:
            self.session.send(action_text)
            self._append_console(f"> {action_text}\n")
        except Exception as e:
            self._append_console(f"[Send failed: {e}]\n")

    # -------------------------
    # Console utilities
    # -------------------------
    def _append_console(self, text):
        self.console.configure(state=tk.NORMAL)
        self.console.insert(tk.END, text)
        self.console.see(tk.END)
        self.console.configure(state=tk.DISABLED)

    # -------------------------
    # Background loop: read from SSH and update console
    # -------------------------
    def _bg_loop(self):
        while self.running:
            try:
                items = self.session.get_now()
                for kind, txt in items:
                    if kind == "OUT":
                        # show remote output
                        self._append_console(txt)
                    elif kind == "AUTO":
                        self._append_console(txt)
                    elif kind == "ERR":
                        self._append_console(f"[ERROR]\n{txt}\n")
                    elif kind == "<CLOSED>":
                        self._append_console("\n[Connection closed by remote]\n")
                        self.status_label.configure(text="Not connected")
                        self.connect_btn.configure(state=tk.NORMAL)
                        self.disconnect_btn.configure(state=tk.DISABLED)
                time.sleep(0.05)
            except Exception:
                time.sleep(0.2)

    def close(self):
        self.running = False
        try:
            self.session.close()
        except Exception:
            pass


# -------------------------
# Helper dialogs
# -------------------------
def simple_dialog_input(parent, title, prompt):
    return simpledialog.askstring(title, prompt, parent=parent)


class DeviceDialog:
    def __init__(self, parent, title="Device", initial=None):
        self.top = tk.Toplevel(parent)
        self.top.title(title)
        self.top.transient(parent)
        self.top.grab_set()
        self.result = None

        if initial is None:
            initial = {"name": "", "ip": "", "username": "localadmin", "password": ""}

        tk.Label(self.top, text="Name:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.name_e = tk.Entry(self.top, width=30)
        self.name_e.grid(row=0, column=1, padx=6, pady=4)
        self.name_e.insert(0, initial.get("name", ""))

        tk.Label(self.top, text="IP:").grid(row=1, column=0, sticky="e", padx=6, pady=4)
        self.ip_e = tk.Entry(self.top, width=30)
        self.ip_e.grid(row=1, column=1, padx=6, pady=4)
        self.ip_e.insert(0, initial.get("ip", ""))

        tk.Label(self.top, text="Username:").grid(row=2, column=0, sticky="e", padx=6, pady=4)
        self.user_e = tk.Entry(self.top, width=30)
        self.user_e.grid(row=2, column=1, padx=6, pady=4)
        self.user_e.insert(0, initial.get("username", "localadmin"))

        tk.Label(self.top, text="Password:").grid(row=3, column=0, sticky="e", padx=6, pady=4)
        self.pw_e = tk.Entry(self.top, width=30, show="*")
        self.pw_e.grid(row=3, column=1, padx=6, pady=4)
        self.pw_e.insert(0, initial.get("password", ""))

        btns = tk.Frame(self.top)
        btns.grid(row=4, column=0, columnspan=2, pady=(6, 8))
        tk.Button(btns, text="OK", width=10, command=self.on_ok).pack(side=tk.LEFT, padx=6)
        tk.Button(btns, text="Cancel", width=10, command=self.on_cancel).pack(side=tk.LEFT, padx=6)

        # center dialog
        self.top.update_idletasks()
        w = self.top.winfo_width()
        h = self.top.winfo_height()
        x = parent.winfo_x() + (parent.winfo_width() - w) // 2
        y = parent.winfo_y() + (parent.winfo_height() - h) // 2
        self.top.geometry(f"+{max(x, 20)}+{max(y, 20)}")

    def on_ok(self):
        name = self.name_e.get().strip()
        ip = self.ip_e.get().strip()
        username = self.user_e.get().strip()
        password = self.pw_e.get()
        if not ip:
            messagebox.showwarning("Missing", "IP is required")
            return
        if not username:
            messagebox.showwarning("Missing", "Username is required")
            return
        self.result = {"name": name or ip, "ip": ip, "username": username, "password": password}
        self.top.destroy()

    def on_cancel(self):
        self.top.destroy()


# -------------------------
# Main
# -------------------------
def main():
    root = tk.Tk()
    app = PDUManagerGUI(root)

    def on_close():
        if messagebox.askokcancel("Quit", "Close PDU Manager?"):
            app.close()
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
