# fetch_suspicious_ip.py
"""
This script fetches a list of suspicious IP addresses from a live blocklist and checks their reputation using the ThreatIntelUtility. It combines static IPs with dynamic ones to provide a comprehensive view of potentially malicious activity. The results are printed in a simple table format indicating whether each IP is considered suspicious or safe.
"""
import requests
import time
from src.security_utils import ThreatIntelUtility

def get_live_threat_ips():
    print("[*] Fetching live suspicious IPs from Blocklist.de...")
    try:
        # Fetch IPs reported in the last 24 hours
        response = requests.get("https://lists.blocklist.de/lists/all.txt", timeout=10)
        if response.status_code == 200:
            return response.text.splitlines()[:15]
    except Exception as e:
        print(f"[-] Failed to fetch blocklist: {e}")
    return []

def main():
    t = ThreatIntelUtility()
    
    # Static IPs + Dynamic ones from the web
    ips_to_check = ["8.8.8.8", "1.1.1.1", "185.220.101.10"]
    live_ips = get_live_threat_ips()
    ips_to_check.extend(live_ips)

    print(f"\n{'IP Address':<15} | {'Suspicious':<10}")
    print("-" * 30)

    for ip in ips_to_check:
        try:
            # Small delay to avoid API rate limits (Max 45/min for ip-api)
            time.sleep(1.4) 
            rep = t.get_ip_reputation(ip)
            is_suspicious = rep.get("is_suspicious", False)
            
            status = "!! YES !!" if is_suspicious else "SAFE"
            print(f"{ip:<15} | {status:<10}")
            
        except Exception as e:
            print(f"[-] Error checking {ip}: {e}")

if __name__ == "__main__":
    main()
