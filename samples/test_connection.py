# test_connection.py
import socket
import time

port = 80
blacklisted_ips = ["54.250.87.83", "213.227.129.32", "89.45.6.18", "149.248.76.110", "193.111.117.226"]

print(f"[*] Starting connection test. Total IPs: {len(blacklisted_ips)}")

for ip in blacklisted_ips:
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

