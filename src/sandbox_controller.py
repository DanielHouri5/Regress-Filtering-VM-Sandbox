# src/sandbox_controller.py
from pathlib import Path
from src.execution_engine import ExecutionEngine
from config import RUNTIME

class SandboxController:
    """
    High-level controller responsible for managing sandbox execution flow.
    """
    def run_sample(self, sample_path: Path):
        """
        Validate and execute a suspicious sample inside the sandbox.

        Args:
            sample_path (Path): Absolute path to the suspicious file provided by the user.

        Returns:
            bool: True if execution completed successfully,
                  False if validation or execution failed.
        """
        # Validate file existence and type before execution.
        if not self._is_valid_sample(Path(sample_path)):
            return False
        
        print("-" * 100)
        print(f"\n[*] Regress filtering started for: {Path(sample_path).name}\n")
        
        try:
            # ExecutionEngine handles container lifecycle + monitoring.
            # Context manager ensures automatic cleanup.
            with ExecutionEngine(Path(sample_path)) as engine:
                engine.run_analysis(runtime_sec=RUNTIME)
            return True
        except Exception as e:
            # Top-level failure handler for execution-related errors.
            print(f"[!] Regress filtering failed: {e}")
            return False

    def _is_valid_sample(self, path: Path):
        """
        Validate that the provided file exists and is a Python script.

        Security constraints:
        - File must exist.
        - File extension must be .py (only Python samples supported).

        Args:
            path (Path): Full sandbox path to validate.

        Returns:
            bool: True if file is valid, otherwise False.
        """

        # Check file existence
        if not path.exists():
            print(f"[!] File not found: {path}")
            return False
        
        # Restrict execution strictly to Python files
        if path.suffix.lower() != '.py':
            print(f"[!] Invalid file type: {path.suffix}")
            return False
        return True
    