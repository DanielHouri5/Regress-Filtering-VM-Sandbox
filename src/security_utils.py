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

    def _normalize_domain(self, domain: str) -> str:
        return domain.strip().rstrip(".").lower() if domain else ""

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
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
        for days_back in [1, 2, 3]:
            try:
                date_str = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')
                url = f"https://www.whoisds.com/whois-database/newly-registered-domains/{date_str}.zip/nrd"
                
                response = requests.get(url, headers=headers, timeout=15) # הוספנו את ה-headers
                print("response: ", response.status_code)
                if response.status_code == 200 and b'PK' in response.content[:2]:
                    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                        for filename in z.namelist():
                            if filename.lower().endswith('.txt'):
                                with z.open(filename) as f:
                                    # חילוץ הדומיינים לקבוצה (set)
                                    content = f.read().decode('utf-8', errors='ignore')
                                    # Normalize to improve matching accuracy.
                                    # - strip whitespace
                                    # - remove trailing dot from FQDNs
                                    # - lowercase
                                    domains = {
                                        line.strip().rstrip(".").lower()
                                        for line in content.splitlines()
                                        if line and line.strip()
                                    }
                                    self.new_domains = domains

                    print("list of new domains: ", list(self.new_domains)[0:5])
                    print(f"[+] Successfully loaded {len(self.new_domains)} new domains.")
                    return True
            except Exception as e:
                print(f"DEBUG: Failed for {date_str}: {e}")
                continue
        return False

    def check_ip_status(self, hostname):
        if not hostname:
            return False
        normalized = hostname.strip().rstrip(".").lower()
        return normalized in self.new_domains

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

    def get_domain_age_info(self, target_ip):
        try:
            target = str(target_ip).strip() if target_ip is not None else ""
            if not target:
                return None, False, None

            # If we already received a hostname, use it directly.
            # If we received an IP, try reverse DNS first.
            normalized_target = self._normalize_domain(target)
            try:
                is_ip = ipaddress.ip_address(target)
            except ValueError:
                is_ip = None

            if is_ip:
                try:
                    domain_name = socket.gethostbyaddr(target)[0]
                except Exception:
                    domain_name = target
            else:
                domain_name = target

            domain_name = self._normalize_domain(domain_name)
            if not domain_name:
                return None, False, None

            # Cache to avoid repeated WHOIS lookups.
            if domain_name in self.domain_age_cache:
                return self.domain_age_cache[domain_name]

            # 2. שאילתת WHOIS
            w = whois.whois(domain_name)
            # 3. חילוץ תאריך יצירה (מטפל במקרה של רשימה או תאריך בודד)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                days_ago = (datetime.now() - creation_date).days
                is_new = days_ago < 60
                result = (domain_name, is_new, days_ago)
                self.domain_age_cache[domain_name] = result
                return result
                
        except Exception as e:
            print(f"Whois lookup failed for {target_ip}: {e}")
            
        return None, False, None

 