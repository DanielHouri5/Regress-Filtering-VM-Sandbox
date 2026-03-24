# src/security_utils.py
from datetime import datetime, timedelta
import socket
import ipaddress
import whois
import requests
import io
import csv
import zipfile
class ThreatIntelUtility:
    """
    ThreatIntelUtility handles fetching and storing a list of known malicious IPs 
    from ThreatFox (abuse.ch) and provides methods to check if a given IP is malicious.
    """
    def __init__(self):
        # Set to store blacklisted IP addresses
        self.blacklisted_ips = set()
        self.new_domains = set()
        self.domain_age_cache = {}  # domain -> (domain, is_new, days_ago)
        self.ip_reputation_cache = {}  # ip -> reputation dict
        # URL to fetch recent malicious IPs in CSV format
        self.url = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"

    def refresh_data(self):
        """
        Fetch the latest threat intelligence data from the ThreatFox CSV feed.
        Parses the CSV and updates the blacklisted_ips set.
        
        Returns:
            bool: True if the data was successfully fetched and parsed, False otherwise.
        """
        try:
            print("[*] Fetching latest threat intelligence...")
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()

            # Use StringIO to read CSV content in memory
            f = io.StringIO(response.text)
            reader = csv.reader(f, delimiter=',', quotechar='"')
            
            new_ips = set()
            for row in reader:
                # Skip empty lines and comments
                if not row or row[0].startswith('#'): continue
                # Extract the IP part from the "IP:Port" field
                ip = row[2].split(':')[0].replace('"', '').strip() 
                new_ips.add(ip)
            
            # Update the current blacklist
            self.blacklisted_ips = new_ips
            print(f"[+] Loaded {len(self.blacklisted_ips)} malicious IPs.")
            print(list(self.blacklisted_ips)[0:5]) 
            return True
        
        except Exception as e:
            print(f"[!] Error updating list: {e}")
            return False

    def is_malicious(self, ip):
        """
        Check if a given IP address is present in the blacklist.

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if the IP is blacklisted, False otherwise.
        """
        result = ip in self.blacklisted_ips
        return result

    def get_ip_reputation(self, ip_address: str):
        """
        Fetch IP reputation-ish metadata from an external API.
        Used as a fallback heuristic when domain-based logic isn't reliable.
        """
        if not ip_address:
            return {
                "is_suspicious": False,
                "reason": "Empty IP",
                "country": "Unknown",
                "isp": "Unknown",
            }

        ip_address = str(ip_address).strip()
        if ip_address in self.ip_reputation_cache:
            return self.ip_reputation_cache[ip_address]

        # Skip private/local IPs.
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_loopback or ip_obj.is_private:
                result = {
                    "is_suspicious": False,
                    "reason": "Internal/Private",
                    "country": "Local",
                    "isp": "Private Network",
                }
                self.ip_reputation_cache[ip_address] = result
                return result
        except ValueError:
            # Not a valid IP - still allow the API call to fail gracefully.
            pass

        try:
            # NOTE: this endpoint can rate-limit; keep timeout short.
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}?fields=status,country,isp,org,mobile,proxy,hosting",
                timeout=5,
            )
            data = response.json()

            if data.get("status") == "success":
                is_suspicious = False
                reason = "Clean"

                # Hosting/Proxy style heuristics.
                if data.get("proxy") or data.get("hosting"):
                    is_suspicious = True
                    reason = "Hosting/Proxy Detected"

                result = {
                    "is_suspicious": is_suspicious,
                    "reason": reason,
                    "country": data.get("country"),
                    "isp": data.get("isp"),
                }
                self.ip_reputation_cache[ip_address] = result
                return result
        except Exception as e:
            # Keep runtime output clean; the caller will use the returned status.
            pass

        result = {
            "is_suspicious": False,
            "reason": "Lookup Failed",
            "country": "Unknown",
            "isp": "Unknown",
        }
        self.ip_reputation_cache[ip_address] = result
        return result