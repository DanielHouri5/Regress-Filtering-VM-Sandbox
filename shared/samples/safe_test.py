import socket
target = "8.8.8.8"
print(f"[*] Testing safe connection to {target}...")
try:
    socket.create_connection((target, 53), timeout=5)
    print("[+] Safe connection established!")
except Exception as e:
    print(f"[-] Failed: {e}")
    