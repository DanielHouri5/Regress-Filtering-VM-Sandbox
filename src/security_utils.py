# src/security_utils.py
import ipaddress
import requests
import io
import csv

class ThreatIntelUtility:
    """
    ThreatIntelUtility handles fetching and storing a list of known malicious IPs 
    from ThreatFox (abuse.ch) and provides methods to check if a given IP is malicious.
    """
    def __init__(self):
        self.blacklisted_ips = set()   # Set to store blacklisted IP addresses
        self.ip_reputation_cache = {}  # ip -> reputation dict
        self.url = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"
        self.headers = {'User-Agent': 'Sandbox-Malware-Monitor/1.0'}

    def fetch_malicious_ips(self):
        """
        Fetch the latest threat intelligence data from the ThreatFox CSV feed.
        """
        try:
            print("[*] Fetching latest threat intelligence from ThreatFox...")
            response = requests.get(self.url, headers=self.headers, timeout=10)
            response.raise_for_status()

            f = io.StringIO(response.text)
            reader = csv.reader(f, delimiter=',', quotechar='"')
            
            new_ips = set()
            for row in reader:
                if not row or row[0].startswith('#'): 
                    continue
                
                try:
                    raw_target = row[2] 
                    ip = raw_target.split(':')[0].replace('"', '').strip()
                    if ip:
                        new_ips.add(ip)
                except IndexError:
                    continue
            
            if new_ips:
                self.blacklisted_ips = new_ips
                print(f"[+] Successfully loaded {len(self.blacklisted_ips)} malicious IPs.")
                print(f"[*] Sample of loaded IPs: {', '.join(list(self.blacklisted_ips)[:5])} ...")
                return True
            else:
                print("[!] Warning: No IPs were parsed from the feed.")
                return False
        
        except Exception as e:
            print(f"[!] Error updating ThreatFox list: {e}")
            return False

    def is_malicious(self, ip):
        """
        Check if a given IP address is present in the ThreatFox blacklist.
        """
        return ip in self.blacklisted_ips

    def get_ip_reputation(self, ip_address: str):
        """
        Fetch IP reputation metadata from IP-API.
        Used for heuristic analysis of 'suspicious' but not necessarily 'blacklisted' IPs.
        """
        if not ip_address:
            return {"is_suspicious": False, "reason": "Empty IP", "country": "Unknown", "isp": "Unknown"}

        ip_address = str(ip_address).strip()
        
        if ip_address in self.ip_reputation_cache:
            return self.ip_reputation_cache[ip_address]

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_loopback or ip_obj.is_private:
                result = {
                    "is_suspicious": False,
                    "reason": "Internal/Private Network",
                    "country": "Local",
                    "isp": "Private",
                }
                self.ip_reputation_cache[ip_address] = result
                return result
        except ValueError:
            return {"is_suspicious": False, "reason": "Invalid IP Format", "country": "N/A", "isp": "N/A"}

        try:
            fields = "status,message,country,isp,org,mobile,proxy,hosting"
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}?fields={fields}",
                timeout=5
            )
            data = response.json()

            if data.get("status") == "success":
                is_suspicious = False
                reasons = []

                if data.get("proxy"):
                    is_suspicious = True
                    reasons.append("Proxy/VPN Detected")
                
                if data.get("hosting"):
                    is_suspicious = True
                    reasons.append("Data Center/Hosting")

                if data.get("mobile") and data.get("proxy"):
                    reasons.append("Mobile Gateway Proxy")

                result = {
                    "is_suspicious": is_suspicious,
                    "reason": " | ".join(reasons) if reasons else "Clean",
                    "country": data.get("country"),
                    "isp": data.get("isp"),
                    "org": data.get("org", data.get("isp"))
                }
                self.ip_reputation_cache[ip_address] = result
                return result

        except Exception as e:
            pass
        
        result = {
            "is_suspicious": False,
            "reason": "Lookup Failed",
            "country": "Unknown",
            "isp": "Unknown",
        }
        return result