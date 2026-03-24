# fetch_suspicious_ip.py
"""
This script fetches a list of suspicious IP addresses from Blocklist.de and 
validates them using our ThreatIntelUtility. It demonstrates how the system 
identifies hosting, proxies, and malicious data centers.
"""
import requests
import time
import sys
import os

# הוספת נתיב הפרויקט כדי שיוכל למצוא את התיקייה src
sys.path.append(os.getcwd())

from src.security_utils import ThreatIntelUtility
from colorama import Fore, Style, init

# אתחול צבעים לטרמינל
init(autoreset=True)

def get_live_threat_ips():
    """
    Fetches a small sample of IPs recently reported for malicious activity.
    """
    print(f"{Fore.CYAN}[*] Fetching live reported IPs from Blocklist.de...")
    try:
        # שליחת User-Agent כדי להיראות כמו דפדפן
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get("https://lists.blocklist.de/lists/all.txt", headers=headers, timeout=10)
        if response.status_code == 200:
            # לוקחים רק 10 כתובות כדי לא לחרוג ממכסת ה-API במהירות
            return list(set(response.text.splitlines()))[:10]
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to fetch blocklist: {e}")
    return []

def main():
    t = ThreatIntelUtility()
    
    # רשימה מעורבת: בטוחים, ידועים כ-VPN/Hosting, ודינמיים מהרשת
    # 185.220.101.10 הוא צומת Tor ידוע (אמור להיות מזוהה כ-Proxy/Hosting)
    ips_to_check = ["8.8.8.8", "1.1.1.1", "185.220.101.10"]
    live_ips = get_live_threat_ips()
    ips_to_check.extend(live_ips)

    print(f"\n{Style.BRIGHT}{'IP ADDRESS':<18} | {'STATUS':<12} | {'COUNTRY':<10} | {'REASON'}")
    print("-" * 80)

    for ip in ips_to_check:
        try:
            # השהיה של 1.5 שניות כדי לכבד את המכסה של ip-api (45 בקשות לדקה)
            time.sleep(1.5) 
            
            # הרצת הלוגיקה שבנית ב-security_utils
            rep = t.get_ip_reputation(ip)
            
            is_suspicious = rep.get("is_suspicious", False)
            country = rep.get("country", "N/A")
            reason = rep.get("reason", "Clean")
            
            if is_suspicious:
                color = Fore.YELLOW
                status = "SUSPICIOUS"
            else:
                color = Fore.GREEN
                status = "SAFE"

            print(f"{color}{ip:<18} | {status:<12} | {country:<10} | {reason}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking {ip}: {e}")

    print("-" * 80)
    print(f"{Fore.CYAN}[*] Analysis complete. Suspicious IPs would be flagged/blocked in the Sandbox.")

if __name__ == "__main__":
    main()