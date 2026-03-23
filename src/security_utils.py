from datetime import datetime, timedelta
import socket
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

    def fetch_new_domains_free(self):
        # הוספת ה-Header הזה היא קריטית!
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        for days_back in [1, 2, 3]:
            try:
                date_str = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')
                url = f"https://www.whoisds.com/whois-database/newly-registered-domains/{date_str}.zip/nrd"
                
                response = requests.get(url, headers=headers, timeout=15) # הוספנו את ה-headers
                
                # בדיקה אם התוכן שחזר הוא באמת ZIP (מתחיל בסימן PK)
                if response.status_code == 200 and b'PK' in response.content[:2]:
                    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                        for filename in z.namelist():
                            if filename.endswith('.txt'):
                                with z.open(filename) as f:
                                    # חילוץ הדומיינים לקבוצה (set)
                                    content = f.read().decode('utf-8')
                                    self.new_domains = set(content.splitlines())
                    print(f"[+] Successfully loaded {len(self.new_domains)} new domains.")
                    return True
            except Exception as e:
                print(f"DEBUG: Failed for {date_str}: {e}")
                continue
        return False

    def check_ip_status(self, hostname):
        result = hostname in self.new_domains
        return result

    def get_domain_age_info(self, target_ip):
        try:
            # 1. ניסיון למצוא שם דומיין לפי IP
            try:
                domain_name = socket.gethostbyaddr(target_ip)[0]
            except:
                domain_name = target_ip # אם אין דומיין, נבדוק את ה-IP ישירות

            # 2. שאילתת WHOIS
            w = whois.whois(domain_name)
            print("w: ", w)
            # 3. חילוץ תאריך יצירה (מטפל במקרה של רשימה או תאריך בודד)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                days_ago = (datetime.now() - creation_date).days
                is_new = days_ago < 60
                return domain_name, is_new, days_ago
                
        except Exception as e:
            print(f"Whois lookup failed for {target_ip}: {e}")
            
        return None, False, None

 