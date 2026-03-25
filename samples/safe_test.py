# test_connection.py
import socket
import time

port = 80
allowed_ips = ["2.2.2.2"]

print(f"[*] Starting connection test. Total IPs: {len(allowed_ips)}")

for ip in allowed_ips:
    print(f"\n[*] Testing connection to: {ip}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3) 
        
        s.connect((ip, port))
        print(f"[+] Connection successful to {ip}")
        s.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
    
    time.sleep(2) 

