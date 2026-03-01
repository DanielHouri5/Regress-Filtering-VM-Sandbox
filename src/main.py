import argparse, sys
from pathlib import Path
from src.sandbox_controller import SandboxController

def main():
    """
    Parse CLI arguments and execute the sandbox workflow.

    Expected argument:
        --sample (str): Path to the suspicious Python file.

    If execution fails (e.g., invalid file, runtime error, or sandbox failure),
    the program exits with a non-zero status code.
    """

    # Configure argument parser for CLI usage
    parser = argparse.ArgumentParser(description="Simple Malware Sandbox")
    # Required argument specifying the path to the suspicious file
    parser.add_argument("--sample", required=True, help="Path to the suspicious file")
    args = parser.parse_args()

    # Initialize the sandbox controller (orchestrates execution + monitoring)
    controller = SandboxController()
    
    # Resolve absolute path
    # Execute the sample inside the sandbox
    # If execution fails, terminate the program with exit code 1
    if not controller.run_sample(Path(args.sample).resolve()):
        sys.exit(1)

if __name__ == "__main__":
    main()
