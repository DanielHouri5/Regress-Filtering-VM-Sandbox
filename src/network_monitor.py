# src/network_monitor.py
import os
import time
from scapy.all import IP, AsyncSniffer , conf
from src.security_utils import ThreatIntelUtility  
from datetime import datetime
from colorama import Fore, Style, init

conf.no_payload_report = True
conf.verb = 0
init(autoreset=True)

class NetworkMonitor:
    def __init__(self, vm_manager=None):
        local_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        report_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(report_dir, exist_ok=True)
        self.log_path = os.path.join(report_dir, f"traffic_log_{local_time}.txt")

        self.allowed_ips = ["127.0.0.1", "8.8.8.8"]
        self.intel_utility = ThreatIntelUtility()
        self.intel_utility.fetch_malicious_ips()
        
        self.suspicious_events = [] 

        self.vm_mgr = vm_manager
        self.total_packets = 0
        
        self.threat_events = [] 
        self.checked_ips = set()
        
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(f"--- Sandbox Network Analysis: {local_time} ---\n\n")

    def start_monitoring(self, runtime_sec, stop_event=None):
        print(f"\n{Fore.CYAN}{'='*65}")
        print(f"{Fore.CYAN}   LIVE NETWORK MONITORING   (Duration: {runtime_sec}s)")
        print(f"{Fore.CYAN}{'='*65}")
        header = f"{'TIME':<10} | {'SOURCE':<15} | {'DESTINATION':<15} | {'STATUS'}"
        print(Fore.WHITE + Style.BRIGHT + header)
        print("-" * 65)

        target_iface = "VirtualBox Host-Only Ethernet Adapter"    
        try:
            sniffer = AsyncSniffer(iface=target_iface, prn=self._process_packet, store=False)
            sniffer.start()

            end_time = time.monotonic() + runtime_sec
            while time.monotonic() < end_time:
                if stop_event is not None and stop_event.is_set():
                    break
                time.sleep(0.5)

            sniffer.stop()
        except Exception as e:
            print(f"\n{Fore.RED}[!] Sniffer Error: {e}")

    def _process_packet(self, packet):
        if not packet.haslayer(IP): return
        self.total_packets += 1

        dest_ip = packet[IP].dst
        src_ip = packet[IP].src
        timestamp = datetime.now().strftime('%H:%M:%S')

        if dest_ip in self.checked_ips: return

        if dest_ip in self.allowed_ips:
            status = "ALLOWED"
            color = Fore.GREEN
        elif self.intel_utility.is_malicious(dest_ip) or self.intel_utility.is_malicious(src_ip):
            self._analyze_and_block(dest_ip)
            status = "BLOCKED"
            color = Fore.RED
        else:
            rep = self.intel_utility.get_ip_reputation(dest_ip)
            if rep.get("is_suspicious"):
                status = f"SUSPICIOUS (IP Reputation: {rep.get('reason')})"
                color = Fore.MAGENTA
                self._record_suspicious(dest_ip, rep)
            else:
                status = "UNAUTHORIZED"
                color = Fore.YELLOW

        self.checked_ips.add(dest_ip)
        print(f"{color}{timestamp:<10} | {src_ip:<15} | {dest_ip:<15} | {status}")

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {src_ip} -> {dest_ip} | {status}\n")

    def _record_suspicious(self, suspicious_ip, rep_data):
        time.sleep(1.5)
        proc_name, pid, _ = self.vm_mgr.get_process_by_ip(suspicious_ip)
        proc_info = f"{proc_name} (PID: {pid})" if proc_name else "Unknown (Too fast to catch)"
        
        country = rep_data.get("country") or "Unknown"
        isp = rep_data.get("isp") or "Unknown"
        reason = rep_data.get("reason") or "Suspicious Reputation"
        
        self.suspicious_events.append({
            "process": proc_info,
            "ip": f"{suspicious_ip} ({country}, {isp})",
            "reason": reason,
            "time": datetime.now().strftime('%H:%M:%S')
        })

    def _analyze_and_block(self, malicious_ip): 
        time.sleep(1.5)       
        proc_name, pid, _ = self.vm_mgr.get_process_by_ip(malicious_ip)
        
        if not proc_name:
            proc_info = "Unknown (Too fast to catch)"
        else:
            proc_info = f"{proc_name} (PID: {pid})"
        
        self.threat_events.append({
            "process": proc_info,
            "ip": malicious_ip,
            "time": datetime.now().strftime('%H:%M:%S')
        })

        try:
            self.vm_mgr.execute_remote(f"sudo iptables -A OUTPUT -d {malicious_ip} -j DROP")
        except:
            pass

    def get_analysis_summary(self):
        blocked_count = len(self.threat_events)
        verdict = "CLEAN"
        color = Fore.GREEN
        recommendation = "File appears safe for execution."
        
        if blocked_count > 0:
            verdict = "MALICIOUS"
            color = Fore.RED
            recommendation = "DANGER: This file attempted to contact known malicious servers."
        elif len(self.suspicious_events) > 0:
            verdict = "SUSPICIOUS (Heuristic)"
            color = Fore.MAGENTA
            recommendation = "Warning: Connections flagged as suspicious by IP reputation."
        
        return {
            "verdict": verdict,
            "color": color,
            "blocked_count": blocked_count,
            "total_packets": self.total_packets,
            "suspicious_events": self.suspicious_events,
            "threat_events": self.threat_events,
            "recommendation": recommendation
        }
        
    def _log_final_report(self, summary):
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"  ANALYSIS COMPLETE - VERDICT: [ {summary['verdict']} ]\n")
            f.write(f"{'='*70}\n")
            f.write(f"  - Total Packets Scanned: {summary['total_packets']}\n")
            f.write(f"  - Malicious Connections: {summary['blocked_count']}\n\n")
            
            f.write(f"  - Processes involved in threats:\n")
            for event in summary['threat_events']:
                f.write(f"    [{event['time']}] Process: {event['process']} | Blocked IP: {event['ip']}\n")
            
            f.write(f"\n  - Suspicious Processes & IPs:\n")
            for s_event in summary['suspicious_events']:
                f.write(f"    [{s_event['time']}] Process: {s_event['process']} | IP: {s_event['ip']} | Reason: {s_event['reason']}\n")
                
            f.write(f"\n  - Recommendation: {summary['recommendation']}\n")
            f.write(f"{'='*70}\n")
    
    def _display_final_report(self):
        summary = self.get_analysis_summary()
        c = summary['color']
        print(f"\n{c}{Style.BRIGHT}{'='*70}")
        print(f"{c}{Style.BRIGHT}  ANALYSIS COMPLETE - VERDICT: [ {summary['verdict']} ]")
        print(f"{c}{Style.BRIGHT}{'='*70}")
        print(f"{Fore.WHITE}  - Total Packets Scanned: {summary['total_packets']}")
        print(f"{Fore.WHITE}  - Malicious Connections: {summary['blocked_count']}")
        
        if summary['threat_events']:
            print(f"\n  - Processes involved in threats:")
            for event in summary['threat_events']:
                print(f"    [{event['time']}] Process: {event['process']} | Blocked IP: {event['ip']}")
        
        if summary['suspicious_events']:
            print(f"{Fore.WHITE}\n  - Suspicious Processes & IPs:")
            for s_event in summary['suspicious_events']:
                print(f"    [{s_event['time']}] Process: {s_event['process']} | IP: {s_event['ip']}")
                print(f"               Reason: {s_event['reason']}")
        
        print(f"\n{c}  Recommendation: {summary['recommendation']}")
        print(f"{c}{Style.BRIGHT}{'='*70}\n")
         
        self._log_final_report(summary)