import os
import time
from scapy.all import IP, TCP, AsyncSniffer , conf
from src import vm_manager
from src.security_utils import ThreatIntelUtility  
from datetime import datetime
from colorama import Fore, Style, init

conf.no_payload_report = True
conf.verb = 0
# Automatically reset terminal color after each print
init(autoreset=True)

class NetworkMonitor:
    """
    Performs behavioral network analysis on sandbox traffic.

    The monitor:
    - Captures outbound and inbound IP packets
    - Checks IPs against threat intelligence blacklist
    - Applies active response (iptables blocking)
    - Tracks statistics for final verdict evaluation
    """
    def __init__(self, vm_manager=None):
        """
        Initialize monitoring environment.

        Args:
            container (Container | None):
                Target container instance (used for applying iptables rules).
        """

        # Timestamped log file for this analysis session
        local_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        # במקום הנתיב הקודם, צור תיקיית reports בתוך הפרויקט
        report_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(report_dir, exist_ok=True)
        self.log_path = os.path.join(report_dir, f"traffic_log_{local_time}.txt")

        # Explicit whitelist (local and known safe IP)
        self.allowed_ips = ["127.0.0.1", "8.8.8.8"]

        # Initialize and refresh external threat intelligence
        self.intel_utility = ThreatIntelUtility()
        self.intel_utility.refresh_data()
        self.suspicious_ips = set() # למעקב בדו"ח הסופי

        self.vm_mgr = vm_manager
        
        # Behavioral tracking counters
        self.blocked_count = 0
        self.total_packets = 0
        self.unique_blocked_ips = set()
        self.detected_processes = set()
        self.checked_ips = set()
        
        # Ensure report directory exists
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        # Create new report file
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(f"--- Sandbox Network Analysis: {local_time} ---\n\n")

    def start_monitoring(self, runtime_sec, stop_event=None):
        """
        Begin live network monitoring session.
        """

        print(f"\n{Fore.CYAN}{'='*65}")
        print(f"{Fore.CYAN}   LIVE NETWORK MONITORING   (Duration: {runtime_sec}s)")
        print(f"{Fore.CYAN}{'='*65}")
        header = f"{'TIME':<10} | {'SOURCE':<15} | {'DESTINATION':<15} | {'STATUS'}"
        print(Fore.WHITE + Style.BRIGHT + header)
        print("-" * 65)

        target_iface = None
        for iface in conf.ifaces.values():
            if hasattr(iface, 'ip') and iface.ip == "192.168.56.1":
                target_iface = iface.name
                break
        
        if not target_iface:
            target_iface = "vboxnet0"
        target_iface = "VirtualBox Host-Only Ethernet Adapter"    
        try:
            # Capture packets using AsyncSniffer so we can stop early.
            sniffer = AsyncSniffer(
                iface=target_iface,
                prn=self._process_packet,
                store=False
            )
            sniffer.start()

            end_time = time.monotonic() + runtime_sec
            while time.monotonic() < end_time:
                if stop_event is not None and stop_event.is_set():
                    break
                time.sleep(0.5)

            sniffer.stop()
        except Exception as e:
            print(f"\n{Fore.RED}[!] Sniffer Error: {e}")
            print(f"{Fore.YELLOW}[*] Hint: Make sure you are running as Administrator!")

    def _process_packet(self, packet):
        """
        Callback function executed for each captured packet.

        Performs:
        - Layer validation
        - Internal traffic filtering
        - Whitelist check
        - Threat intelligence validation
        - Optional active blocking
        - Logging
        """
        # Ignore non-IP packets
        if not packet.haslayer(IP): return
        self.total_packets += 1

        dest_ip = packet[IP].dst
        src_ip = packet[IP].src
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        if dest_ip in self.checked_ips: return
        # Whitelist check
        if dest_ip in self.allowed_ips:
            status = "ALLOWED"
            color = Fore.GREEN
        # elif packet.haslayer(TCP) and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
        #     return
        # Threat intelligence check
        elif self.intel_utility.is_malicious(dest_ip) or self.intel_utility.is_malicious(src_ip):
            self._analyze_and_block(dest_ip)
            status = "BLOCKED"
            color = Fore.RED
        # Non-whitelisted but not blacklisted
        else:
            # Fallback heuristic based on IP metadata (reputation/proxy/hosting).
            rep = self.intel_utility.get_ip_reputation(dest_ip)
            if rep.get("is_suspicious"):
                status = f"SUSPICIOUS (IP Reputation: {rep.get('reason')})"
                color = Fore.LIGHTYELLOW_EX
                country = rep.get("country") or "Unknown"
                isp = rep.get("isp") or "Unknown"
                self.suspicious_ips.add(f"{dest_ip} ({country}, {isp}) - {rep.get('reason')}")
            else:
                status = "UNAUTHORIZED"
                color = Fore.YELLOW

        self.checked_ips.add(dest_ip)
        # Console output
        print(f"{color}{timestamp:<10} | {src_ip:<15} | {dest_ip:<15} | {status}")

        # Append to persistent log
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {src_ip} -> {dest_ip} | {status}\n")
            f.flush()

    def _analyze_and_block(self, malicious_ip):        
        proc_info = self.vm_mgr.get_process_by_ip(malicious_ip)
        
        self.unique_blocked_ips.add(malicious_ip)
        self.detected_processes.add(proc_info)

        self.blocked_count += 1

        if "pid=" in proc_info:
            try:
                pid = proc_info.split("pid=")[1].split(",")[0]
                print(f"{Fore.RED}[*] Terminating Process ID: {pid}...")
                
                self.vm_mgr.execute_remote(f"sudo kill -9 {pid}")
                self.vm_mgr.execute_remote(f"sudo iptables -A OUTPUT -d {malicious_ip} -j DROP")
            except Exception as e:
                print(f"[!] Action failed: {e}")

    def get_analysis_summary(self):
        """
        Generate behavioral security verdict.

        Heuristic logic:
        - If malicious IP contacted → MALICIOUS
        - If excessive traffic (>100 packets) → SUSPICIOUS
        - Otherwise → CLEAN

        Returns:
            dict: Summary containing verdict, stats, and recommendation.
        """
        verdict = "CLEAN"
        color = Fore.GREEN
        recommendation = "File appears safe for execution."
        
        if self.blocked_count > 0:
            verdict = "MALICIOUS"
            color = Fore.RED
            recommendation = "DANGER: This file attempted to contact known malicious servers. DO NOT RUN."
        elif len(self.suspicious_ips) > 0:
            verdict = "SUSPICIOUS (Heuristic)"
            color = Fore.YELLOW
            recommendation = f"Warning: Connections flagged as suspicious by IP reputation: {', '.join(self.suspicious_ips)}"
        elif self.total_packets > 150:
            verdict = "SUSPICIOUS"
            color = Fore.YELLOW
            recommendation = "Warning: Unusual amount of network activity detected."
            
        return {
            "verdict": verdict,
            "color": color,
            "blocked_count": self.blocked_count,
            "unique_ips": list(self.unique_blocked_ips),
            "total_packets": self.total_packets,
            "suspicious_ips": list(self.suspicious_ips),
            "detected_processes": list(self.detected_processes),
            "recommendation": recommendation
        }
    