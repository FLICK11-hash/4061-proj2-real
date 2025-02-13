# Dockerfile
FROM ubuntu:22.04

# Prevent timezone prompt during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install essential tools and C++ development packages
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gdb \
    git \
    curl \
    wget \
    valgrind \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Add deadsnakes PPA for Python 3.10
RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y \
    python3.10 \
    python3.10-dev \
    python3.10-venv \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.10 as the default python3
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1

# Create a symbolic link for python (optional)
RUN ln -s /usr/bin/python3 /usr/bin/python

# Upgrade pip
RUN python3 -m pip install --upgrade pip

WORKDIR /workspace