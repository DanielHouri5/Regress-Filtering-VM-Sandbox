import socket
import time

target = "8.8.8.8"
print(f"[*] Starting persistent connection attempt to {target}...")

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, 80)) 
    except:
        pass 
    time.sleep(0.5)
    