import os
import time
import paramiko

class VMManager:
    """
    Handles lifecycle operations for the sandbox target container.

    Responsibilities:
    - Create isolated execution container
    - Configure networking and capabilities
    - Execute suspicious files within the container
    """

    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.ssh = None

    def connect(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.host, username=self.user, password=self.password)
   
    def upload_file(self, local_path, remote_path):
        sftp = self.ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()

    def get_process_by_ip(self, target_ip):
        # אנחנו מחפשים בלוג שנוצר בתוך ה-VM
        cmd = f"grep {target_ip} /tmp/network_log.txt | tail -n 1"

        # The monitoring thread can detect a "malicious" IP before the VM log
        # has that exact entry flushed to /tmp/network_log.txt.
        # Retry briefly on empty output to make parsing deterministic.
        last_raw_output = ""
        for _ in range(3):
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            raw_output = stdout.read().decode().strip()
            if raw_output:
                last_raw_output = raw_output
                break
            time.sleep(0.8)

        # Keep parsing behavior identical, just more reliable when empty.
        if "users:((" in last_raw_output:
            try:
                output = last_raw_output.split("users:((")[1].split("))")[0]
                parts = output.split(",")
                process_name = parts[0].strip('"')  # מוריד את הגרשיים
                pid = parts[1].split("=")[1]
                fd = parts[2].split("=")[1]
                return process_name, pid, fd
            except (IndexError, ValueError) as e:
                print(f"Parsing error: {e}")

        return None, None, None

    def execute_remote(self, command):
        return self.ssh.exec_command(command)
    
    def cleanup(self, remote_path):
        try:
            print(f"[*] Cleaning up remote file: {remote_path}")
            self.ssh.exec_command(f"rm -f {remote_path}")
            self.ssh.exec_command("sudo iptables -F")
        except:
            pass

    def close(self):
        if self.ssh:
            self.ssh.close()
