import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import paramiko
import smtplib
from email.mime.text import MIMEText
import logging
import time
import re
import threading
import json
import os
from queue import Queue # For thread-safe GUI updates
#---- Import python libaries

# --- Configuration Defaults (can be overridden by GUI settings) ---
CONFIG_FILE = 'server_monitor_config.json'
DEFAULT_SETTINGS = {
    "disk_threshold_percent": 80,
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "smtp_user": "youremail@example.com",
    "smtp_password": "your_email_password",
    "sender_email": "monitor@example.com",
    "receiver_emails": ["admin@example.com"],
    "monitoring_interval_seconds": 300 # 5 minutes
}

# --- Logging (to GUI and optionally to file) ---
log_queue = Queue()

def setup_logger():
    # Basic logger, GUI will pull from log_queue
    logger = logging.getLogger("ServerMonitor")
    logger.setLevel(logging.INFO)
    # You can add a FileHandler here if you want logs to a file as well
    # fh = logging.FileHandler('server_monitor_gui.log')
    # fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    # logger.addHandler(fh)
    return logger

logger = setup_logger()

# --- SSH and Monitoring Core Logic ---
def send_email_notification(subject, body, settings):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = settings['sender_email']
        msg['To'] = ', '.join(settings['receiver_emails'])

        with smtplib.SMTP(settings['smtp_server'], int(settings['smtp_port'])) as server:
            server.ehlo()
            if int(settings['smtp_port']) != 25: # Assuming TLS for common ports like 587
                server.starttls()
                server.ehlo()
            server.login(settings['smtp_user'], settings['smtp_password'])
            server.sendmail(settings['sender_email'], settings['receiver_emails'], msg.as_string())
        log_queue.put(f"INFO: Email notification sent: {subject}")
    except Exception as e:
        log_queue.put(f"ERROR: Failed to send email: {e}")

def connect_ssh(server_info):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        auth_method = server_info.get('auth_method', 'key')
        if auth_method == 'key' and server_info.get('key_path'):
            key_path_expanded = os.path.expanduser(server_info['key_path']) # Expand ~
            pkey = paramiko.RSAKey.from_private_key_file(key_path_expanded)
            client.connect(server_info['host'], port=int(server_info['port']), username=server_info['user'], pkey=pkey, timeout=10)
        elif auth_method == 'password' and server_info.get('password'):
            client.connect(server_info['host'], port=int(server_info['port']), username=server_info['user'], password=server_info['password'], timeout=10)
        else:
            log_queue.put(f"ERROR: No valid SSH auth method for {server_info['host']}")
            return None
        return client
    except Exception as e:
        log_queue.put(f"ERROR: SSH connection to {server_info['host']} failed: {e}")
        return None

def get_available_drives(ssh_client, server_host):
    drives = []
    try:
        cmd = "df -P | awk 'NR>1 {print $6}' | grep -vE '^(/dev/loop|/run|/sys|/proc|/tmp|/var/lib/docker|tmpfs|devtmpfs|overlay|squashfs|udev|cgroupfs|none|snap)'"
        stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=10)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            log_queue.put(f"WARNING: Error fetching drives from {server_host}: {error}")
            return []
        if output:
            drives = [line for line in output.split('\n') if line.strip()]
        return sorted(list(set(drives)))
    except Exception as e:
        log_queue.put(f"ERROR: Exception fetching drives from {server_host}: {e}")
        return []

def get_disk_usage_for_selected_drives(ssh_client, server_host, selected_drives, threshold):
    disk_alerts = []
    disk_info_lines = []
    if not selected_drives:
        return [], f"Disk Usage on {server_host}: No drives selected for monitoring."

    try:
        df_command_drives = " ".join(f'"{drive}"' for drive in selected_drives) # Quote drive paths
        cmd = f"df -P {df_command_drives} | awk 'NR>1'"
        stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=15)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            log_queue.put(f"WARNING: Error getting disk usage from {server_host} for {', '.join(selected_drives)}: {error}")
            return [], f"Disk Usage on {server_host}: Error - {error}"

        lines = output.split('\n')
        parsed_mount_points = {} # To handle if df output for a single requested path shows sub-paths

        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                filesystem = parts[0]
                use_percent_str = parts[4].replace('%', '')
                mount_point = parts[5]
                parsed_mount_points[mount_point] = {'filesystem': filesystem, 'use_percent_str': use_percent_str}

        for mp_requested in selected_drives:
            if mp_requested in parsed_mount_points:
                data = parsed_mount_points[mp_requested]
                try:
                    use_percent = int(data['use_percent_str'])
                    disk_info_lines.append(f"  {mp_requested} ({data['filesystem']}): {use_percent}%")
                    if use_percent > threshold:
                        alert_message = (f"ALERT! Disk {mp_requested} on {server_host} "
                                         f"is {use_percent}% full (Threshold: {threshold}%).")
                        disk_alerts.append(alert_message)
                except ValueError:
                    log_queue.put(f"WARNING: Could not parse disk usage for {data['filesystem']} on {server_host}")
            else:
                log_queue.put(f"WARNING: Requested drive {mp_requested} not found in df output on {server_host}")
                disk_info_lines.append(f"  {mp_requested}: Not found or error in df output")


        disk_info_str = f"Disk Usage on {server_host} (Monitored Drives):\n" + "\n".join(disk_info_lines)
        if not disk_info_lines:
             disk_info_str = f"Disk Usage on {server_host}: No data retrieved for monitored drives."
        return disk_alerts, disk_info_str.strip()

    except Exception as e:
        log_queue.put(f"ERROR: Exception getting disk usage from {server_host}: {e}")
        return [], f"Disk Usage on {server_host}: Exception - {e}"


def get_cpu_load(ssh_client, server_host):
    try:
        cmd = "uptime"
        stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=10)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            log_queue.put(f"WARNING: Error getting CPU load from {server_host}: {error}")
            return f"CPU Load on {server_host}: Error - {error}"

        match = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", output)
        if match:
            load_1m, load_5m, load_15m = match.groups()
            return f"CPU Load on {server_host}: 1m={load_1m}, 5m={load_5m}, 15m={load_15m}"
        else:
            log_queue.put(f"WARNING: Could not parse load average from {server_host}: {output}")
            return f"CPU Load on {server_host}: Could not parse."
    except Exception as e:
        log_queue.put(f"ERROR: Exception getting CPU load from {server_host}: {e}")
        return f"CPU Load on {server_host}: Exception - {e}"

# --- GUI Classes ---
# --- Only needed for the GUI
 
class ServerConfigDialog(tk.Toplevel):
    def __init__(self, parent, server_info=None, app_settings=None):
        super().__init__(parent)
        self.transient(parent)
        self.parent = parent
        self.app_settings = app_settings
        self.result = None
        self.server_info_initial = server_info if server_info else {}
        self.title("Server Configuration")
        self.geometry("550x600")
        self.grab_set()

        self.host_var = tk.StringVar(value=self.server_info_initial.get('host', ''))
        self.port_var = tk.StringVar(value=str(self.server_info_initial.get('port', '22')))
        self.user_var = tk.StringVar(value=self.server_info_initial.get('user', ''))
        self.auth_method_var = tk.StringVar(value=self.server_info_initial.get('auth_method', 'key'))
        self.key_path_var = tk.StringVar(value=self.server_info_initial.get('key_path', ''))
        self.password_var = tk.StringVar(value=self.server_info_initial.get('password', ''))
        self.selected_drives_vars = {}
        self.initial_selected_drives = self.server_info_initial.get('selected_drives', [])

        frame = ttk.Frame(self, padding="10")
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Host/IP:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(frame, textvariable=self.host_var, width=40).grid(row=0, column=1, columnspan=2, sticky=tk.EW, pady=2)
        ttk.Label(frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(frame, textvariable=self.port_var, width=10).grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=2)
        ttk.Label(frame, text="Username:").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Entry(frame, textvariable=self.user_var, width=40).grid(row=2, column=1, columnspan=2, sticky=tk.EW, pady=2)

        ttk.Label(frame, text="Auth Method:").grid(row=3, column=0, sticky=tk.W, pady=2)
        auth_frame = ttk.Frame(frame)
        auth_frame.grid(row=3, column=1, columnspan=2, sticky=tk.EW)
        ttk.Radiobutton(auth_frame, text="SSH Key", variable=self.auth_method_var, value="key", command=self.toggle_auth_fields).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(auth_frame, text="Password", variable=self.auth_method_var, value="password", command=self.toggle_auth_fields).pack(side=tk.LEFT, padx=5)

        self.key_path_label = ttk.Label(frame, text="Key Path:")
        self.key_path_entry = ttk.Entry(frame, textvariable=self.key_path_var, width=30)
        self.browse_key_button = ttk.Button(frame, text="Browse", command=self.browse_key_file)

        self.password_label = ttk.Label(frame, text="Password:")
        self.password_entry = ttk.Entry(frame, textvariable=self.password_var, show="*", width=30)
        
        # Position auth fields based on initial selection
        self.toggle_auth_fields() # Call this early

        fetch_drives_button = ttk.Button(frame, text="Fetch Available Drives", command=self.fetch_and_display_drives)
        fetch_drives_button.grid(row=6, column=0, columnspan=3, pady=(10,5)) # Adjusted row

        drives_outer_frame = ttk.LabelFrame(frame, text="Drives to Monitor", padding=5)
        drives_outer_frame.grid(row=7, column=0, columnspan=3, sticky=tk.NSEW, pady=5) # Adjusted row
        frame.grid_rowconfigure(7, weight=1)

        self.drives_canvas = tk.Canvas(drives_outer_frame)
        self.drives_scrollbar = ttk.Scrollbar(drives_outer_frame, orient="vertical", command=self.drives_canvas.yview)
        self.drives_scrollable_frame = ttk.Frame(self.drives_canvas)
        self.drives_scrollable_frame.bind("<Configure>", lambda e: self.drives_canvas.configure(scrollregion=self.drives_canvas.bbox("all")))
        self.drives_canvas.create_window((0, 0), window=self.drives_scrollable_frame, anchor="nw")
        self.drives_canvas.configure(yscrollcommand=self.drives_scrollbar.set)
        self.drives_canvas.pack(side="left", fill="both", expand=True)
        self.drives_scrollbar.pack(side="right", fill="y")

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=8, column=0, columnspan=3, pady=10, sticky=tk.E) # Adjusted row
        ttk.Button(button_frame, text="Save", command=self.on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.LEFT, padx=5)

        if self.server_info_initial.get('host') and self.initial_selected_drives:
             self.populate_drive_checkboxes(self.initial_selected_drives, self.initial_selected_drives)

    def toggle_auth_fields(self):
        # Define a common row for these elements to avoid overlap issues
        auth_detail_row = 4
        if self.auth_method_var.get() == "key":
            self.key_path_label.grid(row=auth_detail_row, column=0, sticky=tk.W, pady=2)
            self.key_path_entry.grid(row=auth_detail_row, column=1, sticky=tk.EW, pady=2)
            self.browse_key_button.grid(row=auth_detail_row, column=2, sticky=tk.W, pady=2, padx=5)
            self.password_label.grid_remove()
            self.password_entry.grid_remove()
        else: # password
            self.key_path_label.grid_remove()
            self.key_path_entry.grid_remove()
            self.browse_key_button.grid_remove()
            self.password_label.grid(row=auth_detail_row, column=0, sticky=tk.W, pady=2)
            self.password_entry.grid(row=auth_detail_row, column=1, columnspan=2, sticky=tk.EW, pady=2)

    def browse_key_file(self):
        filepath = filedialog.askopenfilename(title="Select SSH Private Key", initialdir=os.path.expanduser("~/.ssh"))
        if filepath:
            self.key_path_var.set(filepath)

    def fetch_and_display_drives(self):
        host = self.host_var.get()
        port = self.port_var.get()
        user = self.user_var.get()
        auth_method = self.auth_method_var.get()
        key_path = self.key_path_var.get()
        password = self.password_var.get()

        if not all([host, port, user]):
            messagebox.showerror("Error", "Host, Port, and User are required to fetch drives.", parent=self)
            return

        temp_server_info = {'host': host, 'port': int(port), 'user': user, 'auth_method': auth_method}
        if auth_method == 'key':
            if not key_path: messagebox.showerror("Error", "SSH Key path is required.", parent=self); return
            temp_server_info['key_path'] = key_path
        else:
            if not password: messagebox.showerror("Error", "Password is required.", parent=self); return
            temp_server_info['password'] = password

        log_queue.put(f"INFO: Attempting to fetch drives for {host}...")
        self.update_idletasks() # Ensure log message appears
        ssh = connect_ssh(temp_server_info)
        if ssh:
            available_drives = get_available_drives(ssh, host)
            ssh.close()
            if available_drives:
                log_queue.put(f"INFO: Found drives on {host}: {', '.join(available_drives)}")
                self.populate_drive_checkboxes(available_drives, self.initial_selected_drives)
            else:
                log_queue.put(f"INFO: No suitable drives found or error fetching from {host}.")
                messagebox.showinfo("Drives", f"No suitable drives found on {host} or connection issue. Check logs.", parent=self)
                self.populate_drive_checkboxes([], [])
        else:
            messagebox.showerror("Connection Failed", f"Could not connect to {host} to fetch drives. Check logs.", parent=self)
            self.populate_drive_checkboxes([], [])

    def populate_drive_checkboxes(self, drives_list, pre_selected_drives):
        for widget in self.drives_scrollable_frame.winfo_children(): widget.destroy()
        self.selected_drives_vars.clear()
        if not drives_list: ttk.Label(self.drives_scrollable_frame, text="No drives to display.").pack(pady=5); return
        for drive_mount_point in drives_list:
            var = tk.BooleanVar(value=(drive_mount_point in pre_selected_drives))
            cb = ttk.Checkbutton(self.drives_scrollable_frame, text=drive_mount_point, variable=var)
            cb.pack(anchor=tk.W, padx=5)
            self.selected_drives_vars[drive_mount_point] = var

    def on_save(self):
        host = self.host_var.get(); port_str = self.port_var.get(); user = self.user_var.get()
        auth_method = self.auth_method_var.get(); key_path = self.key_path_var.get(); password = self.password_var.get()
        if not all([host, port_str, user]): messagebox.showerror("Error", "Host, Port, and User are required.", parent=self); return
        try: port = int(port_str)
        except ValueError: messagebox.showerror("Error", "Port must be a number.", parent=self); return
        if auth_method == 'key' and not key_path: messagebox.showerror("Error", "SSH Key path is required for key-based auth.", parent=self); return

        selected_drives_list = [dp for dp, var in self.selected_drives_vars.items() if var.get()]
        if not selected_drives_list:
             if not messagebox.askyesno("No Drives Selected", "No drives are selected for monitoring. Save anyway?", parent=self): return

        self.result = {'host': host, 'port': port, 'user': user, 'auth_method': auth_method, 'key_path': key_path, 'password': password, 'selected_drives': selected_drives_list}
        self.destroy()

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent, current_settings):
        super().__init__(parent)
        self.transient(parent); self.parent = parent; self.result = None
        self.title("Application Settings"); self.geometry("500x400"); self.grab_set()
        self.settings_vars = {}
        frame = ttk.Frame(self, padding="10"); frame.pack(expand=True, fill=tk.BOTH)
        fields = {"disk_threshold_percent": "Disk Full Threshold (%):", "monitoring_interval_seconds": "Monitoring Interval (s):",
                  "smtp_server": "SMTP Server:", "smtp_port": "SMTP Port:", "smtp_user": "SMTP User:",
                  "smtp_password": "SMTP Password:", "sender_email": "Sender Email:", "receiver_emails": "Receiver Emails (comma-sep):"}
        row_idx = 0
        for key, label_text in fields.items():
            ttk.Label(frame, text=label_text).grid(row=row_idx, column=0, sticky=tk.W, pady=3)
            var = tk.StringVar(value=str(current_settings.get(key, DEFAULT_SETTINGS.get(key, ''))))
            self.settings_vars[key] = var
            entry = ttk.Entry(frame, textvariable=var, width=40, show="*" if "password" in key else None)
            entry.grid(row=row_idx, column=1, sticky=tk.EW, pady=3)
            row_idx += 1
        frame.columnconfigure(1, weight=1)
        button_frame = ttk.Frame(frame); button_frame.grid(row=row_idx, column=0, columnspan=2, pady=10, sticky=tk.E)
        ttk.Button(button_frame, text="Save", command=self.on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.LEFT, padx=5)

    def on_save(self):
        self.result = {}
        for key, var in self.settings_vars.items():
            val = var.get()
            if key in ["disk_threshold_percent", "smtp_port", "monitoring_interval_seconds"]:
                try: self.result[key] = int(val)
                except ValueError: messagebox.showerror("Error", f"Invalid number for {key}", parent=self); return
            elif key == "receiver_emails": self.result[key] = [e.strip() for e in val.split(',') if e.strip()]
            else: self.result[key] = val
        self.destroy()

class ServerMonitorApp:
    def __init__(self, root_window): # Renamed root to root_window for clarity
        self.root = root_window # Keep self.root for consistency with Tkinter examples
        self.root.title("Server Cluster Monitor")
        self.root.geometry("800x600")

        self.servers = []
        self.settings = DEFAULT_SETTINGS.copy()
        self.monitoring_active = False
        self.monitor_thread = None

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        left_frame = ttk.Frame(main_frame, width=250)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_frame.pack_propagate(False)

        ttk.Label(left_frame, text="Servers:", font=("Arial", 12, "bold")).pack(pady=5)
        self.server_listbox = tk.Listbox(left_frame, height=10, exportselection=False)
        self.server_listbox.pack(fill=tk.X, pady=5)

        server_buttons_frame = ttk.Frame(left_frame)
        server_buttons_frame.pack(fill=tk.X)
        ttk.Button(server_buttons_frame, text="Add", command=self.add_server).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(server_buttons_frame, text="Edit", command=self.edit_server).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(server_buttons_frame, text="Remove", command=self.remove_server).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        ttk.Separator(left_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        self.monitor_button = ttk.Button(left_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.monitor_button.pack(fill=tk.X, pady=5)
        ttk.Button(left_frame, text="Settings", command=self.open_settings).pack(fill=tk.X, pady=5)
        ttk.Button(left_frame, text="Save Configuration", command=self.save_config_explicitly).pack(fill=tk.X, pady=5)

        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)
        ttk.Label(right_frame, text="Monitoring Log:", font=("Arial", 12, "bold")).pack(pady=5, anchor=tk.W)
        self.log_text = tk.Text(right_frame, height=15, wrap=tk.WORD, state=tk.DISABLED)
        log_scrollbar = ttk.Scrollbar(right_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(expand=True, fill=tk.BOTH)

        self.load_config() # Load after all widgets are created
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.update_log_display()

    def log_message(self, message):
        if hasattr(self, 'log_text') and self.log_text.winfo_exists():
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.configure(state=tk.DISABLED)
            self.log_text.see(tk.END)
        else:
            print(f"LOG (GUI not ready): {message}")


    def update_log_display(self):
        try:
            while not log_queue.empty():
                message = log_queue.get_nowait()
                logger.info(message) # Log to Python's logger as well
                self.log_message(message)
        except Exception: pass
        if hasattr(self, 'root') and self.root.winfo_exists():
            self.root.after(100, self.update_log_display)

    def update_server_listbox(self):
        if hasattr(self, 'server_listbox') and self.server_listbox.winfo_exists():
            self.server_listbox.delete(0, tk.END)
            for server in self.servers:
                drives_str = f" ({len(server.get('selected_drives',[]))} drives)" if server.get('selected_drives') else " (No drives)"
                self.server_listbox.insert(tk.END, f"{server['host']}{drives_str}")

    def add_server(self):
        dialog = ServerConfigDialog(self.root, app_settings=self.settings)
        self.root.wait_window(dialog)
        if dialog.result:
            self.servers.append(dialog.result)
            self.update_server_listbox()
            log_queue.put(f"INFO: Added server: {dialog.result['host']}")

    def edit_server(self):
        selected_idx = self.server_listbox.curselection()
        if not selected_idx: messagebox.showwarning("No Selection", "Select server to edit.", parent=self.root); return
        idx = selected_idx[0]
        dialog = ServerConfigDialog(self.root, server_info=self.servers[idx].copy(), app_settings=self.settings)
        self.root.wait_window(dialog)
        if dialog.result:
            self.servers[idx] = dialog.result
            self.update_server_listbox()
            log_queue.put(f"INFO: Edited server: {dialog.result['host']}")

    def remove_server(self):
        selected_idx = self.server_listbox.curselection()
        if not selected_idx: messagebox.showwarning("No Selection", "Select server to remove.", parent=self.root); return
        idx = selected_idx[0]
        if messagebox.askyesno("Confirm Delete", f"Remove {self.servers[idx]['host']}?", parent=self.root):
            server_host = self.servers[idx]['host']
            del self.servers[idx]
            self.update_server_listbox()
            log_queue.put(f"INFO: Removed server: {server_host}")

    def open_settings(self):
        dialog = SettingsDialog(self.root, self.settings.copy())
        self.root.wait_window(dialog)
        if dialog.result:
            self.settings.update(dialog.result)
            log_queue.put("INFO: Application settings updated.")

    def save_config_explicitly(self):
        self.save_config()
        messagebox.showinfo("Saved", f"Configuration saved to {CONFIG_FILE}", parent=self.root)

    def save_config(self):
        config_data = {"servers": self.servers, "settings": self.settings}
        try:
            with open(CONFIG_FILE, 'w') as f: json.dump(config_data, f, indent=4)
            log_queue.put(f"INFO: Configuration saved to {CONFIG_FILE}")
        except IOError as e:
            log_queue.put(f"ERROR: Could not save configuration: {e}")
            if hasattr(self, 'root') and self.root.winfo_exists(): # Check if GUI is available for messagebox
                 messagebox.showerror("Save Error", f"Could not save config: {e}", parent=self.root)


    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f: config_data = json.load(f)
                self.servers = config_data.get("servers", [])
                loaded_settings = config_data.get("settings", {})
                temp_settings = DEFAULT_SETTINGS.copy(); temp_settings.update(loaded_settings)
                self.settings = temp_settings
                log_queue.put(f"INFO: Configuration loaded from {CONFIG_FILE}")
            else: log_queue.put(f"INFO: No config file ({CONFIG_FILE}). Using defaults.")
        except (IOError, json.JSONDecodeError) as e:
            log_queue.put(f"ERROR: Could not load config: {e}. Using defaults.")
            if hasattr(self, 'root') and self.root.winfo_exists():
                messagebox.showwarning("Load Error", f"Error loading config: {e}\nUsing defaults.", parent=self.root)
        self.update_server_listbox()

    def toggle_monitoring(self):
        if self.monitoring_active: self.stop_monitoring()
        else: self.start_monitoring()

    def start_monitoring(self):
        if not self.servers: messagebox.showwarning("No Servers", "Add servers before monitoring.", parent=self.root); return
        self.monitoring_active = True
        self.monitor_button.config(text="Stop Monitoring")
        log_queue.put("INFO: === Monitoring Started ===")
        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring_active = False
        if hasattr(self, 'monitor_button') and self.monitor_button.winfo_exists():
            self.monitor_button.config(text="Start Monitoring")
        log_queue.put("INFO: === Monitoring Stoppped ===")

    def monitoring_loop(self):
        while self.monitoring_active:
            log_queue.put("INFO: --- Starting new monitoring cycle ---")
            for server_conf in list(self.servers): # Iterate over a copy in case list is modified
                if not self.monitoring_active: break
                log_queue.put(f"INFO: Connecting to {server_conf['host']}...")
                ssh = connect_ssh(server_conf)
                if ssh:
                    try:
                        selected_drives = server_conf.get('selected_drives', [])
                        if selected_drives:
                            disk_alerts, disk_status_str = get_disk_usage_for_selected_drives(
                                ssh, server_conf['host'], selected_drives, self.settings['disk_threshold_percent']
                            )
                            log_queue.put(f"INFO: {disk_status_str}")
                            for alert in disk_alerts:
                                log_queue.put(f"ALERT: {alert}")
                                send_email_notification(f"Disk Alert on {server_conf['host']}", alert, self.settings)
                        else: log_queue.put(f"INFO: No drives selected for disk monitoring on {server_conf['host']}.")
                        cpu_load_str = get_cpu_load(ssh, server_conf['host'])
                        log_queue.put(f"INFO: {cpu_load_str}")
                    except Exception as e: log_queue.put(f"ERROR: Error during monitoring {server_conf['host']}: {e}")
                    finally: ssh.close(); log_queue.put(f"INFO: Disconnected from {server_conf['host']}")
                else:
                    log_queue.put(f"ERROR: Could not connect to {server_conf['host']}. Skipping.")
                    # send_email_notification(f"Connection Failed: {server_conf['host']}", f"Failed to connect to server {server_conf['host']} for monitoring.", self.settings)
            if not self.monitoring_active: break
            wait_time = self.settings.get('monitoring_interval_seconds', 300)
            log_queue.put(f"INFO: --- Cycle finished. Waiting {wait_time} seconds... ---")
            for _ in range(wait_time):
                if not self.monitoring_active: break
                time.sleep(1)
        log_queue.put("INFO: Monitoring loop ended.")

    def on_closing(self):
        if self.monitoring_active:
            if messagebox.askokcancel("Quit", "Monitoring active. Stop and quit?", parent=self.root):
                self.stop_monitoring()
                self.root.after(200, self._actual_close) # Give thread a moment
            else: return
        else: self._actual_close()

    def _actual_close(self):
        self.save_config()
        self.monitoring_active = False # Ensure loop exits if it was in a long sleep
        if self.monitor_thread and self.monitor_thread.is_alive():
            # Actively join can cause GUI to hang if thread is stuck.
            # Daemon threads will exit when main exits, but this is a "best effort"
            # self.monitor_thread.join(timeout=1) # Optional: wait a bit
            pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerMonitorApp(root)
    root.mainloop()