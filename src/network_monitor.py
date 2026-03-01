import os
from scapy.all import sniff, IP
from src.security_utils import ThreatIntelUtility  
from datetime import datetime
from colorama import Fore, Style, init

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
    def __init__(self, container=None):
        """
        Initialize monitoring environment.

        Args:
            container (Container | None):
                Target container instance (used for applying iptables rules).
        """

        # Timestamped log file for this analysis session
        local_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        self.log_path = f"/sandbox/shared/reports/traffic_log_{local_time}.txt"

        # Explicit whitelist (local and known safe IP)
        self.allowed_ips = ["127.0.0.1", "8.8.8.8"]

        # Initialize and refresh external threat intelligence
        self.intel_utility = ThreatIntelUtility()
        self.intel_utility.refresh_data()

        self.container = container
        
        # Behavioral tracking counters
        self.blocked_count = 0
        self.total_packets = 0
        self.unique_blocked_ips = set()
        
        # Ensure report directory exists
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        # Create new report file
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(f"--- Sandbox Network Analysis: {local_time} ---\n\n")

    def start_monitoring(self, runtime_sec):
        """
        Begin live network monitoring session.

        Args:
            runtime_sec (int): Duration (seconds) to monitor traffic.
        """
        print(f"\n{Fore.CYAN}{'='*65}")
        print(f"{Fore.CYAN}  LIVE NETWORK MONITORING  (Duration: {runtime_sec}s)")
        print(f"{Fore.CYAN}{'='*65}")
        header = f"{'TIME':<10} | {'SOURCE':<15} | {'DESTINATION':<15} | {'STATUS'}"
        print(Fore.WHITE + Style.BRIGHT + header)
        print("-" * 65)
        
        # Capture only IP packets on eth0 interface
        sniff(iface="eth0", filter="ip", prn=self._process_packet, timeout=runtime_sec, store=0)

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
        
        # Ignore internal Docker bridge communication
        if dest_ip.startswith("172.") and src_ip.startswith("172."): return

        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Whitelist check
        if dest_ip in self.allowed_ips:
            status = "ALLOWED"
            color = Fore.GREEN

        # Threat intelligence check
        elif self.intel_utility.is_malicious(dest_ip) or self.intel_utility.is_malicious(src_ip):
            malicious_ip = dest_ip if self.intel_utility.is_malicious(dest_ip) else src_ip

            # Apply dynamic firewall rule
            self._block_ip(malicious_ip)

            status = "BLOCKED (MALICIOUS)"
            color = Fore.RED
            
            # Track unique malicious IPs
            if malicious_ip not in self.unique_blocked_ips:
                self.unique_blocked_ips.add(malicious_ip)
                self.blocked_count += 1

        # Non-whitelisted but not blacklisted
        else:
            status = "UNAUTHORIZED"
            color = Fore.YELLOW

        # Console output
        print(f"{color}{timestamp:<10} | {src_ip:<15} | {dest_ip:<15} | {status}")

        # Append to persistent log
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {src_ip} -> {dest_ip} | {status}\n")
            f.flush()

    def _block_ip(self, ip_address):
        """
        Dynamically block malicious IP via iptables rules
        inside the sandbox container.

        Args:
            ip_address (str): IP address to block.
        """
        if self.container and ip_address not in self.allowed_ips:
            # Block outbound traffic to malicious IP
            self.container.exec_run(f"iptables -A OUTPUT -d {ip_address} -j DROP")
            # Block inbound traffic from malicious IP
            self.container.exec_run(f"iptables -A INPUT -s {ip_address} -j DROP")

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
        elif self.total_packets > 100:
            verdict = "SUSPICIOUS"
            color = Fore.YELLOW
            recommendation = "Warning: Unusual amount of network activity detected."
            
        return {
            "verdict": verdict,
            "color": color,
            "blocked_count": self.blocked_count,
            "unique_ips": list(self.unique_blocked_ips),
            "total_packets": self.total_packets,
            "recommendation": recommendation
        }
    