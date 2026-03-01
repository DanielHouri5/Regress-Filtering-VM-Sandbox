# test_connection.py
import socket

target_ip = "38.29.212.164" 
port = 80

print(f"[*] Starting connection test to {target_ip}...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target_ip, port))
    print("[+] Connection successful (This shouldn't happen if blocked!)")
    s.close()
except Exception as e:
    print(f"[!] Connection failed as expected: {e}")
    