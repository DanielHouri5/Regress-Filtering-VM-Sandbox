import threading
import time
from pathlib import Path
from colorama import Fore, Style
from src.vm_manager import VMManager 
from src.network_monitor import NetworkMonitor
from config import HOST, USER, PASSWORD

class ExecutionEngine:
    """
    Orchestrates the full lifecycle of sandbox execution.

    Responsibilities:
    - Provision isolated container
    - Start live network monitoring
    - Execute suspicious file
    - Collect behavioral data
    - Produce final verdict
    - Ensure proper teardown
    """

    def __init__(self, sample_path):
        """
        Initialize execution engine state.

        Args:
            sample_path (Path | str): Path to the suspicious file.
        """
        self.sample_path = Path(sample_path)
        self.vm_mgr = VMManager(
            host=HOST, 
            user=USER, 
            password=PASSWORD
        )
        self.monitor = None

    def __enter__(self):
        print(f"{Fore.CYAN}[*] Connecting to Analysis VM ({self.vm_mgr.host})...")
        try:
            self.vm_mgr.connect()
            self.monitor = NetworkMonitor(vm_manager=self.vm_mgr)
            return self
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize VM environment: {e}")
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit point.

        Ensures container is stopped and removed,
        even if execution fails.
        """
        print(f"\n{Fore.CYAN}[*] Tearing down environment...")
        remote_path = f"/tmp/{self.sample_path.name}"
        self.vm_mgr.cleanup(remote_path)
        self.vm_mgr.close()

    def run_analysis(self, runtime_sec):
        """
        Execute the suspicious sample while performing live network monitoring.

        Workflow:
        1. Start monitoring in a background thread.
        2. Execute sample inside container.
        3. Wait for monitoring window to finish.
        4. Display final security report.

        Args:
            runtime_sec (int): Duration (seconds) for monitoring window.
        """
        print(f"[*] Starting monitoring thread for {runtime_sec}s...")
        remote_path = f"/tmp/{self.sample_path.name}"
        print(f"[*] Uploading sample to VM: {remote_path}")
        self.vm_mgr.upload_file(str(self.sample_path), remote_path)

        stop_event = threading.Event()
        # Launch monitoring in a separate daemon thread
        monitor_thread = threading.Thread(
            target=self.monitor.start_monitoring,
            args=(runtime_sec, stop_event)
        )
        monitor_thread.start()
        
        # Short delay to ensure monitoring is active before execution begins
        time.sleep(2) 
        try:
            # Exec returns immediately; stdout/stderr channels become ready when command exits.
            _stdin, stdout, _stderr = self.vm_mgr.execute_remote(f"python3 {remote_path}")

            start_time = time.monotonic()
            while time.monotonic() - start_time < runtime_sec:
                if stdout.channel.exit_status_ready():
                    break
                time.sleep(1)
        except Exception as e:
            print(f"[!] Execution error: {e}")
        finally:
            # Stop monitoring as soon as the VM execution ends (or runtime_sec is reached).
            stop_event.set()

        # Wait for monitoring thread to stop cleanly
        monitor_thread.join()
        
        # Generate final behavioral verdict
        self._display_final_report()

    def _display_final_report(self):
        summary = self.monitor.get_analysis_summary()
        c = summary['color']
        
        print(f"\n{c}{Style.BRIGHT}{'='*70}")
        print(f"{c}{Style.BRIGHT}  ANALYSIS COMPLETE - VERDICT: [ {summary['verdict']} ]")
        print(f"{c}{Style.BRIGHT}{'='*70}")
        print(f"{Fore.WHITE}  - Total Packets Scanned: {summary['total_packets']}")
        print(f"{Fore.WHITE}  - Malicious Connections: {summary['blocked_count']}")
        
        if summary['detected_processes']:
            print(f"{Fore.YELLOW}\n  - Processes involved in threats:")
            for proc in summary['detected_processes']:
                print(f"    [!] {proc}")
        
        print(f"{Fore.WHITE}\n  - Unique Blocked IPs: {summary['unique_ips']}")
        print(f"{Fore.WHITE}  - Detected Processes: {summary['detected_processes']}")
        print(f"\n{c}  Recommendation: {summary['recommendation']}")
        print(f"{c}{Style.BRIGHT}{'='*70}\n")
            