# src/execution_engine.py
import threading
import time
from pathlib import Path
from colorama import Fore, Style
from src.vm_manager import VMManager 
from src.network_monitor import NetworkMonitor
from config import HOST, USER, PASSWORD

class ExecutionEngine:
    def __init__(self, sample_path):
        self.sample_path = Path(sample_path)
        self.vm_mgr = VMManager(host=HOST, user=USER, password=PASSWORD)
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
        print(f"\n{Fore.CYAN}[*] Tearing down environment...")
        remote_path = f"/tmp/{self.sample_path.name}"
        self.vm_mgr.cleanup(remote_path)
        self.vm_mgr.close()

    def run_analysis(self, runtime_sec):
            remote_path = f"/tmp/{self.sample_path.name}"
            print(f"[*] Uploading sample: {self.sample_path.name}")
            self.vm_mgr.upload_file(str(self.sample_path), remote_path)

            print(f"[*] Starting analysis window ({runtime_sec}s)...")
            print(f"[*] Executing sample inside VM: {remote_path}")

            stop_event = threading.Event()
            monitor_thread = threading.Thread(
                target=self.monitor.start_monitoring,
                args=(runtime_sec, stop_event)
            )
            monitor_thread.start()
            
            time.sleep(1) 
            try:
                self.vm_mgr.execute_remote(f"python3 {remote_path}")
                monitor_thread.join()
                
            except Exception as e:
                print(f"[!] Error: {e}")
            finally:
                stop_event.set()
                if monitor_thread.is_alive():
                    monitor_thread.join()

            self.monitor._display_final_report()