import threading
import time
from pathlib import Path
from colorama import Fore, Style
from src.container_manager import ContainerManager
from src.network_monitor import NetworkMonitor

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
        self.container_mgr = ContainerManager()
        self.container = None
        self.monitor = None

    def __enter__(self):
        """
        Context manager entry point.

        Creates and starts an isolated container environment,
        then initializes the network monitor.

        Returns:
            ExecutionEngine: Self instance for chained execution.
        """
        print("[*] Setting up isolated environment...")

        # Create sandbox container
        self.container = self.container_mgr.create_container()
        self.container.start()

        # Initialize live network monitor bound to container
        self.monitor = NetworkMonitor(container=self.container)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit point.

        Ensures container is stopped and removed,
        even if execution fails.
        """
        if self.container:
            print(f"\n[*] Cleaning up: Stopping and removing container...")
            print("-" * 100)
            try:
                self.container.stop(timeout=2)
                self.container.remove()
            except:
                # Suppress cleanup errors to avoid masking original exception
                pass

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
        
        # Launch monitoring in a separate daemon thread
        monitor_thread = threading.Thread(target=self.monitor.start_monitoring, args=(runtime_sec,))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Short delay to ensure monitoring is active before execution begins
        time.sleep(2) 

        print(f"[*] Executing sample: {self.sample_path.name}")
        try:
            # Execute suspicious file inside isolated container
            result = self.container_mgr.exec_sample(self.container, self.sample_path.name)
            print("-" * 30)
            print("[*] Sample Console Output:")

            # Display console output from executed sample
            print(result.output.decode().strip() or "[No Output]")
            print("-" * 30)
        except Exception as e:
            print(f"[!] Execution error: {e}")

        # Wait for monitoring thread to complete or timeout
        monitor_thread.join(timeout=runtime_sec)
        
        # Generate final behavioral verdict
        self._display_final_report()

    def _display_final_report(self):
        """
        Display summarized behavioral analysis results.

        Report includes:
        - Final security verdict
        - Packet count
        - Number of blocked malicious IPs
        - Unique blocked IP list
        - Recommended action
        """
        summary = self.monitor.get_analysis_summary()
        c = summary['color']
        
        print(f"\n{c}{Style.BRIGHT}{'='*65}")
        print(f"{c}{Style.BRIGHT}  FINAL SECURITY VERDICT: [ {summary['verdict']} ]")
        print(f"{c}{Style.BRIGHT}{'='*65}")
        print(f"{Fore.WHITE}  - Analyzed Packets: {summary['total_packets']}")
        print(f"{Fore.WHITE}  - Malicious Blocks: {summary['blocked_count']}")
        
        if summary['unique_ips']:
            print(f"{Fore.WHITE}  - Blocked IPs: {', '.join(summary['unique_ips'])}")
            
        print(f"\n{c}{Style.BRIGHT}  RECOMMENDATION: {summary['recommendation']}")
        print(f"{c}{'='*65}\n")
        