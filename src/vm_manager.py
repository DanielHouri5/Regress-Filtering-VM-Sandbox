import os
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
        stdin, stdout, stderr = self.ssh.exec_command(cmd)
        output = stdout.read().decode().strip()
        
        if output:
            # הפלט ייראה בערך ככה: 17:05:12 tcp ESTAB ... users:(("firefox",pid=2345,fd=67))
            if "users:((" in output:
                try:
                    proc_info = output.split('users:((')[1].split('))')[0]
                    return proc_info # יחזיר "firefox",pid=2345
                except:
                    pass
            return "Process match found in logs"
            
        return "Unknown Process (No log entry)"

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
