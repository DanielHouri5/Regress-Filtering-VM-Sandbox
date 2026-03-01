import socket
import time

DESTINATIONS = {
    "ALLOWED (Whitelist)": "8.8.8.8",       
    "UNKNOWN (Not in lists)": "140.82.114.22", 
    "MALICIOUS (Blacklist)": "43.249.175.199"        
}

def attempt_connection(name, ip, port=80):
    print(f"[*] Testing {name} connection to {ip}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3) 
        
        result = s.connect_ex((ip, port))
        
        if result == 0:
            print(f"[+] SUCCESS: Connection to {name} ({ip}) established.")
        else:
            print(f"[-] FAILED: Connection to {name} ({ip}) failed (Error code: {result}).")
        
        s.close()
    except Exception as e:
        print(f"[!] ERROR connecting to {name}: {e}")

print("--- Starting Network Behavior Simulation ---")

for name, ip in DESTINATIONS.items():
    attempt_connection(name, ip)
    print("-" * 40)
    time.sleep(1) 

print("--- Simulation Finished ---")
