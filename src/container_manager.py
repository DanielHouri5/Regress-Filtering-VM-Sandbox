import os
import socket
import docker
from pathlib import Path

class ContainerManager:
    """
    Handles lifecycle operations for the sandbox target container.

    Responsibilities:
    - Create isolated execution container
    - Configure networking and capabilities
    - Execute suspicious files within the container
    """

    def __init__(self, image_name="sandbox-runtime"):
        """
        Initialize Docker client and runtime configuration.

        Args:
            image_name (str): Docker image used for executing suspicious samples.
        """
        self.client = docker.from_env()
        self.image_name = image_name

        # Hostname is used as container ID when running inside Docker.
        # This enables sharing the network namespace with the controller container.
        self.controller_id = socket.gethostname()

        # Shared host directory used for samples and reports.
        self.host_path = os.environ.get("HOST_SHARED_PATH")

    def create_container(self):
        """
        Create a new sandbox target container.

        The container:
        - Shares network namespace with controller
        - Mounts samples as read-only
        - Mounts reports as read-write
        - Grants necessary capabilities for iptables manipulation

        Returns:
            docker.models.containers.Container: Created (but not started) container.

        Raises:
            Exception: If required environment variable is missing.
        """
        if not self.host_path:
            raise Exception("Environment variable 'HOST_SHARED_PATH' is missing.")

        # Define volume bindings between host and container
        volumes = {
            # Suspicious samples (read-only for safety)
            f"{self.host_path}/samples": {"bind": "/sandbox/shared/samples", "mode": "ro"},
            # Reports directory (write-enabled for logs)
            f"{self.host_path}/reports": {"bind": "/sandbox/shared/reports", "mode": "rw"}
        }
        
        # Create container with controlled environment
        return self.client.containers.create(
            image=self.image_name,

            # Keep container alive until explicit execution
            command=["tail", "-f", "/dev/null"],

            volumes=volumes,

            # Share network namespace with controller container
            # This enables external traffic monitoring from controller
            network_mode=f"container:{self.controller_id}", 

            # Required for firewall manipulation and packet control
            privileged=True,
            
            detach=True,
            tty=True,
            stdin_open=True,
            cap_add=["NET_ADMIN", "NET_RAW"],
            name="sandbox_target"
        )

    def exec_sample(self, container, sample_filename):
        """
        Execute a suspicious Python sample inside the container.

        Args:
            container (Container): Active Docker container instance.
            sample_filename (str): Name of the Python file to execute.

        Returns:
            ExecResult: Docker execution result object containing output and exit code.
        """

        # Construct internal container path
        path_in_container = f"/sandbox/shared/samples/{sample_filename}"

        # Execute sample using Python interpreter inside container
        return container.exec_run(f"python3 {path_in_container}")
    