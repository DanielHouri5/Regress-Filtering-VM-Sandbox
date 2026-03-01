import requests
import io
import csv

class ThreatIntelUtility:
    """
    ThreatIntelUtility handles fetching and storing a list of known malicious IPs 
    from ThreatFox (abuse.ch) and provides methods to check if a given IP is malicious.
    """
    def __init__(self):
        # Set to store blacklisted IP addresses
        self.blacklisted_ips = set()
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
    
 