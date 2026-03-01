# Dockerfile for the main malware sandbox environment
# Base image: Python 3.12 slim version for a lightweight Python environment
FROM python:3.12-slim

# Install system dependencies required for sandbox operations:
# - libpcap-dev: for packet capture with Scapy
# - gcc: for compiling any Python extensions
# - docker.io: to allow the container to manage other containers
# - iptables: to enable blocking of malicious IPs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    docker.io \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /sandbox

# Set PYTHONPATH to include /sandbox for module imports
ENV PYTHONPATH=/sandbox

# Copy requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire sandbox source code into the container
COPY . .

# Set the container entrypoint to run the main sandbox module
ENTRYPOINT ["python3", "-m", "src.main"]
