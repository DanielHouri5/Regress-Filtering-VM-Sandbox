import argparse, sys
from pathlib import Path

def _import_sandbox_controller_silently():
    """
    Avoid startup noise from third-party libraries (warnings/print noise)
    that gets emitted during import-time.
    """
    import contextlib
    import io
    import warnings

    # Suppress known import-time deprecation warnings.
    try:
        from cryptography.utils import CryptographyDeprecationWarning
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    except Exception:
        pass

    # Suppress generic deprecation warnings during import of libraries.
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    buf_out = io.StringIO()
    buf_err = io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        from src.sandbox_controller import SandboxController

    return SandboxController

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
    SandboxController = _import_sandbox_controller_silently()
    controller = SandboxController()
    
    # Resolve absolute path
    # Execute the sample inside the sandbox
    # If execution fails, terminate the program with exit code 1
    if not controller.run_sample(Path(args.sample).resolve()):
        sys.exit(1)

if __name__ == "__main__":
    main()
