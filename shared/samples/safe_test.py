import socket
import time

target = "206.189.88.100"
print(f"[*] Starting persistent connection attempt to {target}...")

while True: # לולאה אינסופית - המערכת שלך תהרוג את התהליך הזה עם kill -9
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, 80)) 
    except:
        pass # זה בסדר שזה נכשל, אנחנו רק רוצים שה-OS ירשום את הניסיון
    time.sleep(0.5)
    