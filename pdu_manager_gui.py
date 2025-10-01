"""
PDU Manager GUI
Author: Ahmed Aldulaimi
Description: GUI tool to manage and control Tripp-Lite / Eaton PDUs over SSH with robust device detection.
"""

__author__ = "Ahmed Aldulaimi"
__version__ = "2.0"

#!/usr/bin/env python3
import json
import threading
import queue
import os
import time
from functools import partial
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

# Requires paramiko
try:
    import paramiko
except Exception as e:
    raise SystemExit("Paramiko is required. Install with: pip install paramiko") from e

SAVE_FILE_DEFAULT = "pdus.json"

# Template commands — after detecting device ID
command_templates = {
    "on": "device {device} > output {outlet} on",
    "off": "device {device} > output {outlet} off",
    "reboot": "device {device} > restart",
}

# --- SSH helper functions ---
def ssh_run_command(host, username, password, outlet=None, action=None):
    """
    Connects via SSH, detects device ID, then runs the correct outlet command.
    Returns (success, output).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, username=username, password=password, timeout=10)
        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(9999)  # clear initial banner

        # Detect device ID
        shell.send("show device\n")
        time.sleep(2)
        out = ""
        while True:
            if shell.recv_ready():
                out += shell.recv(9999).decode(errors="ignore")
            else:
                break
        lines = out.splitlines()
        device_id = None
        for line in lines:
            parts = line.strip().split()
            if len(parts) > 0 and parts[0].startswith("Device"):
                device_id = parts[0]
                break
        if not device_id:
            client.close()
            return False, "Could not detect device ID"

        # Send the action command
        cmd = command_templates[action].format(device=device_id, outlet=outlet)
        # Split commands by '>' for multi-step
        for c in cmd.split(">"):
            shell.send(c.strip() + "\n")
            time.sleep(1)
            shell.recv(9999)  # clear output
        # Exit
        shell.send("exit\n")
        time.sleep(1)
        client.close()
        return True, f"Action '{action}' executed on device {device_id} outlet {outlet}"
    except Exception as e:
        return False, str(e)

# --- GUI app ---
class PDUManagerApp:
    def __init__(self, root):
        self.root = root
        root.title("PDU Manager GUI")
        self.pdus = []  # list of dicts {name, ip, user, pass}
        self.log_queue = queue.Queue()

        # Header fun text
        header = ttk.Label(root, text="With great power comes great responsibility", font=("Helvetica", 14, "bold"))
        header.grid(row=0, column=0, columnspan=2, pady=4)

        # UI frames
        left = ttk.Frame(root, padding=8)
        left.grid(row=1, column=0, sticky="nswe")
        right = ttk.Frame(root, padding=8)
        right.grid(row=1, column=1, sticky="nswe")

        # Left: PDU list and controls
        ttk.Label(left, text="Saved PDUs").grid(row=0, column=0, sticky="w")
        self.pdu_listbox = tk.Listbox(left, width=36, height=16, selectmode=tk.EXTENDED)
        self.pdu_listbox.grid(row=1, column=0, columnspan=3, pady=(4,8))

        btn_frame = ttk.Frame(left)
        btn_frame.grid(row=2, column=0, sticky="we", pady=(4,0))
        ttk.Button(btn_frame, text="Add", command=self.add_pdu).grid(row=0, column=0, padx=4)
        ttk.Button(btn_frame, text="Edit", command=self.edit_pdu).grid(row=0, column=1, padx=4)
        ttk.Button(btn_frame, text="Remove", command=self.remove_pdu).grid(row=0, column=2, padx=4)

        file_frame = ttk.Frame(left)
        file_frame.grid(row=3, column=0, sticky="we", pady=(8,0))
        ttk.Button(file_frame, text="Load", command=self.load_pdus).grid(row=0, column=0, padx=4)
        ttk.Button(file_frame, text="Save", command=self.save_pdus).grid(row=0, column=1, padx=4)
        ttk.Button(file_frame, text="Save As...", command=self.save_pdus_as).grid(row=0, column=2, padx=4)

        # Right: Controls and log
        ctl_frame = ttk.LabelFrame(right, text="Controls", padding=8)
        ctl_frame.grid(row=0, column=0, sticky="we")

        ttk.Label(ctl_frame, text="Outlet #:").grid(row=0, column=0, sticky="w")
        self.outlet_entry = ttk.Entry(ctl_frame, width=6)
        self.outlet_entry.grid(row=0, column=1, sticky="w", padx=(4,8))
        self.outlet_entry.insert(0, "1")

        ttk.Button(ctl_frame, text="Turn ON", command=partial(self.broadcast_action, "on")).grid(row=0, column=2, padx=4)
        ttk.Button(ctl_frame, text="Turn OFF", command=partial(self.broadcast_action, "off")).grid(row=0, column=3, padx=4)
        ttk.Button(ctl_frame, text="Reboot", command=partial(self.broadcast_action, "reboot")).grid(row=0, column=4, padx=4)

        ttk.Separator(ctl_frame, orient=tk.HORIZONTAL).grid(row=1, column=0, columnspan=6, pady=8, sticky="we")

        # Log / output area
        log_frame = ttk.LabelFrame(right, text="Log / Output", padding=4)
        log_frame.grid(row=1, column=0, pady=(8,0), sticky="nsew")
        right.rowconfigure(1, weight=1)
        self.log_text = tk.Text(log_frame, width=80, height=20, wrap="none")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Status bar
        self.status = tk.StringVar(value="Ready")
        ttk.Label(root, textvariable=self.status, relief="sunken").grid(row=2, column=0, columnspan=2, sticky="we", pady=(4,0))

        # Load default file if present
        if os.path.exists(SAVE_FILE_DEFAULT):
            try:
                self.load_pdus(SAVE_FILE_DEFAULT)
            except Exception:
                pass

        # Start log queue processor
        self.root.after(200, self.process_log_queue)

    # --- PDU list management ---
    def add_pdu(self):
        data = self.pdu_dialog()
        if data:
            self.pdus.append(data)
            self.refresh_listbox()
            self.save_pdus(SAVE_FILE_DEFAULT)

    def edit_pdu(self):
        sel = self.pdu_listbox.curselection()
        if not sel:
            messagebox.showinfo("Edit PDU", "Select a PDU to edit.")
            return
        idx = sel[0]
        data = self.pdu_dialog(self.pdus[idx])
        if data:
            self.pdus[idx] = data
            self.refresh_listbox()
            self.save_pdus(SAVE_FILE_DEFAULT)

    def remove_pdu(self):
        sels = list(self.pdu_listbox.curselection())
        if not sels:
            messagebox.showinfo("Remove PDU", "Select PDU(s) to remove.")
            return
        for i in reversed(sels):
            del self.pdus[i]
        self.refresh_listbox()
        self.save_pdus(SAVE_FILE_DEFAULT)

    def pdu_dialog(self, existing=None):
        dlg = tk.Toplevel(self.root)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.title("Add / Edit PDU")
        ttk.Label(dlg, text="Name (friendly):").grid(row=0, column=0, sticky="e")
        name_e = ttk.Entry(dlg, width=30)
        name_e.grid(row=0, column=1, pady=4)
        ttk.Label(dlg, text="IP / Host:").grid(row=1, column=0, sticky="e")
        ip_e = ttk.Entry(dlg, width=30)
        ip_e.grid(row=1, column=1, pady=4)
        ttk.Label(dlg, text="Username:").grid(row=2, column=0, sticky="e")
        user_e = ttk.Entry(dlg, width=30)
        user_e.grid(row=2, column=1, pady=4)
        ttk.Label(dlg, text="Password:").grid(row=3, column=0, sticky="e")
        pass_e = ttk.Entry(dlg, width=30, show="*")
        pass_e.grid(row=3, column=1, pady=4)
        if existing:
            name_e.insert(0, existing.get("name", ""))
            ip_e.insert(0, existing.get("ip", ""))
            user_e.insert(0, existing.get("user", "localadmin"))
            pass_e.insert(0, existing.get("password", ""))
        btnf = ttk.Frame(dlg)
        btnf.grid(row=4, column=0, columnspan=2, pady=(8,0))
        def on_ok():
            name = name_e.get().strip() or ip_e.get().strip()
            ip = ip_e.get().strip()
            if not ip:
                messagebox.showerror("Error", "IP/Host is required.")
                return
            data = {"name": name, "ip": ip, "user": user_e.get().strip(), "password": pass_e.get()}
            dlg.destroy()
            dlg.update()
            return_data[0] = data
        def on_cancel():
            dlg.destroy()
        return_data = [None]
        ttk.Button(btnf, text="OK", command=on_ok).grid(row=0, column=0, padx=8)
        ttk.Button(btnf, text="Cancel", command=on_cancel).grid(row=0, column=1, padx=8)
        self.root.wait_window(dlg)
        return return_data[0]

    def refresh_listbox(self):
        self.pdu_listbox.delete(0, tk.END)
        for p in self.pdus:
            display = f"{p.get('name','')}  ({p.get('ip')})"
            self.pdu_listbox.insert(tk.END, display)

    def load_pdus(self, filename=None):
        if not filename:
            filename = filedialog.askopenfilename(title="Load PDUs JSON", filetypes=[("JSON", "*.json"), ("All", "*.*")])
            if not filename:
                return
        with open(filename, "r") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Invalid file format")
        self.pdus = data
        self.refresh_listbox()
        self.status.set(f"Loaded {len(self.pdus)} PDUs from {os.path.basename(filename)}")

    def save_pdus(self, filename=None):
        if not filename:
            filename = SAVE_FILE_DEFAULT
        with open(filename, "w") as f:
            json.dump(self.pdus, f, indent=2)
        self.status.set(f"Saved {len(self.pdus)} PDUs to {os.path.basename(filename)}")

    def save_pdus_as(self):
        filename = filedialog.asksaveasfilename(title="Save PDUs JSON", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not filename:
            return
        self.save_pdus(filename)

    # --- Actions ---
    def broadcast_action(self, action_key):
        outlet = self.outlet_entry.get().strip()
        if not outlet:
            messagebox.showerror("Error", "Enter an outlet number.")
            return
        sels = list(self.pdu_listbox.curselection())
        if not sels:
            messagebox.showinfo("No PDUs", "Select target PDUs from the left list.")
            return
        targets = [self.pdus[i] for i in sels]
        for p in targets:
            thread = threading.Thread(target=self._worker_run, args=(p, outlet, action_key), daemon=True)
            thread.start()

    def _worker_run(self, pdu, outlet, action_key):
        name = pdu.get("name") or pdu.get("ip")
        ip = pdu.get("ip")
        user = pdu.get("user") or "localadmin"
        pw = pdu.get("password") or ""
        self.log_queue.put(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Connecting to {name} ({ip})...\n")
        ok, out = ssh_run_command(ip, user, pw, outlet, action_key)
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        if ok:
            self.log_queue.put(f"[{t}] {name} ({ip}) action={action_key} outlet={outlet} OK\n")
        else:
            self.log_queue.put(f"[{t}] {name} ({ip}) FAILED\n{out}\n")
        self.status.set("Done")

    def process_log_queue(self):
        while not self.log_queue.empty():
            try:
                text = self.log_queue.get_nowait()
            except queue.Empty:
                break
            self.log_text.insert(tk.END, text)
            self.log_text.see(tk.END)
        self.root.after(200, self.process_log_queue)

# --- run ---
def main():
    root = tk.Tk()
    app = PDUManagerApp(root)
    root.geometry("980x640")
    root.mainloop()

if __name__ == "__main__":
    main()
