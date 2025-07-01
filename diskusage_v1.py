# --- Non GUI Version (Pretty Sure)

import paramiko
import smtplib
from email.mime.text import MIMEText
import logging
import time
import re # For parsing uptime

# --- Configuration ---
# Server Cluster Details
# For key-based auth, provide 'key_path'. For password-based, provide 'password'.
# Key-based authentication is STRONGLY recommended.
SERVERS = [
    {
        'host': 'server1.example.com', # Replace with actual hostname or IP
        'port': 22,
        'user': 'your_ssh_user',
        'key_path': '/path/to/your/private_key_file' # e.g., '~/.ssh/id_rsa'
        # 'password': 'your_ssh_password' # Uncomment and use if not using key_path
    },
    {
        'host': '192.168.1.101', # Another server
        'port': 22,
        'user': 'another_user',
        'key_path': '/path/to/another/private_key_file'
    },
    # Add more servers as needed
]

# Disk Usage Threshold
DISK_FULL_THRESHOLD_PERCENT = 80

# Email Notification Settings
SMTP_SERVER = 'smtp.example.com' # Your SMTP server
SMTP_PORT = 587 # Or 465 for SSL, 25 for no encryption
SMTP_USER = 'youremail@example.com'
SMTP_PASSWORD = 'your_email_password'
SENDER_EMAIL = 'monitor@example.com' # Can be same as SMTP_USER
RECEIVER_EMAILS = ['admin1@example.com', 'admin2@example.com'] # List of recipients

# Logging Configuration
LOG_FILE = 'server_monitor.log'
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def send_email_notification(subject, body):
    """Sends an email notification."""
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = ', '.join(RECEIVER_EMAILS)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls() # Use TLS encryption
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
        logging.info(f"Email notification sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

def connect_ssh(server_info):
    """Establishes an SSH connection to a server."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Auto-accept host key
    try:
        if 'key_path' in server_info and server_info['key_path']:
            pkey = paramiko.RSAKey.from_private_key_file(server_info['key_path'])
            client.connect(
                server_info['host'],
                port=server_info['port'],
                username=server_info['user'],
                pkey=pkey,
                timeout=10
            )
        elif 'password' in server_info and server_info['password']:
            client.connect(
                server_info['host'],
                port=server_info['port'],
                username=server_info['user'],
                password=server_info['password'],
                timeout=10
            )
        else:
            logging.error(f"No valid authentication method (key or password) for {server_info['host']}")
            return None
        return client
    except Exception as e:
        logging.error(f"SSH connection to {server_info['host']} failed: {e}")
        return None

def get_disk_usage(ssh_client, server_host):
    """Retrieves disk usage statistics from the server."""
    disk_alerts = []
    try:
        # 'df -P' provides POSIX standard output, easier to parse
        # Exclude tmpfs, devtmpfs, overlay, squashfs etc.
        # Modify the grep -v pattern as needed for your environment
        cmd = "df -P | awk 'NR>1' | grep -vE 'tmpfs|devtmpfs|overlay|squashfs|loop|udev'"
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            logging.warning(f"Error getting disk usage from {server_host}: {error}")
            return [], f"Error: {error}"

        if not output:
            logging.warning(f"No disk usage output from {server_host}")
            return [], "No disk usage output"

        lines = output.split('\n')
        disk_info_str = f"Disk Usage on {server_host}:\n"
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                filesystem = parts[0]
                # total = parts[1] # 1K-blocks
                # used = parts[2]
                # available = parts[3]
                use_percent_str = parts[4].replace('%', '')
                mount_point = parts[5]

                try:
                    use_percent = int(use_percent_str)
                    disk_info_str += f"  {mount_point} ({filesystem}): {use_percent}%\n"
                    if use_percent > DISK_FULL_THRESHOLD_PERCENT:
                        alert_message = (f"ALERT! Disk {mount_point} on {server_host} "
                                         f"is {use_percent}% full (Threshold: {DISK_FULL_THRESHOLD_PERCENT}%).")
                        disk_alerts.append(alert_message)
                except ValueError:
                    logging.warning(f"Could not parse disk usage percentage '{use_percent_str}' for {filesystem} on {server_host}")
            else:
                logging.warning(f"Could not parse disk line: '{line}' on {server_host}")
        return disk_alerts, disk_info_str.strip()

    except Exception as e:
        logging.error(f"Exception getting disk usage from {server_host}: {e}")
        return [], f"Exception: {e}"

def get_cpu_load(ssh_client, server_host):
    """Retrieves CPU load average from the server."""
    try:
        cmd = "uptime"
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            logging.warning(f"Error getting CPU load from {server_host}: {error}")
            return f"CPU Load on {server_host}: Error - {error}"

        # Example uptime output:
        # 10:30:00 up 5 days,  1:20,  2 users,  load average: 0.05, 0.10, 0.15
        match = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", output)
        if match:
            load_1m, load_5m, load_15m = match.groups()
            return f"CPU Load on {server_host}: 1min={load_1m}, 5min={load_5m}, 15min={load_15m}"
        else:
            logging.warning(f"Could not parse load average from uptime output on {server_host}: {output}")
            return f"CPU Load on {server_host}: Could not parse uptime output."

    except Exception as e:
        logging.error(f"Exception getting CPU load from {server_host}: {e}")
        return f"CPU Load on {server_host}: Exception - {e}"


# --- Main Monitoring Logic ---
def monitor_servers():
    logging.info("--- Starting Server Monitoring Cycle ---")
    overall_status_report = []

    for server_config in SERVERS:
        server_host = server_config['host']
        logging.info(f"Connecting to {server_host}...")
        ssh = connect_ssh(server_config)

        if ssh:
            try:
                # Get Disk Usage
                disk_alerts, disk_status_str = get_disk_usage(ssh, server_host)
                overall_status_report.append(disk_status_str)
                if disk_alerts:
                    for alert in disk_alerts:
                        logging.warning(alert)
                        send_email_notification(f"Disk Alert on {server_host}", alert)

                # Get CPU Load
                cpu_load_str = get_cpu_load(ssh, server_host)
                logging.info(cpu_load_str)
                overall_status_report.append(cpu_load_str)

            except Exception as e:
                logging.error(f"Error during monitoring {server_host}: {e}")
                overall_status_report.append(f"Error monitoring {server_host}: {e}")
            finally:
                ssh.close()
                logging.info(f"Disconnected from {server_host}")
        else:
            logging.error(f"Could not connect to {server_host}. Skipping.")
            overall_status_report.append(f"Could not connect to {server_host}. Monitoring skipped.")
            # Optionally send a notification if connection fails repeatedly
            send_email_notification(f"Connection Failed: {server_host}",
                                    f"Failed to connect to server {server_host} for monitoring.")


    # You could send a summary report periodically if desired
    # summary_subject = "Server Cluster Status Report"
    # summary_body = "\n\n".join(overall_status_report)
    # send_email_notification(summary_subject, summary_body) # Uncomment if you want a full report
    logging.info("--- Server Monitoring Cycle Finished ---")


if __name__ == "__main__":
    # Example: Run monitoring every 5 minutes
    # For a real deployment, you might use cron or a systemd timer
    # instead of a Python loop with sleep.
    # For this example, we'll just run it once.
    monitor_servers()

    # To run continuously (simple example):
    # try:
    #     while True:
    #         monitor_servers()
    #         logging.info("Waiting for 300 seconds before next check...")
    #         time.sleep(300) # 5 minutes
    # except KeyboardInterrupt:
    #     logging.info("Monitoring script stopped by user.")
