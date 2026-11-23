# PANDA container used by the hy2 orchestrators (hy2/orch/panda_docker.py)
# Build: docker build -t hy2-panda docker/panda
FROM pandare/panda:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends genisoimage python3-pip && \
    rm -rf /var/lib/apt/lists/*

# Python deps imported by hy2/orch/* and hy2/core/{utils,dt_table}.py
ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN python3 -m pip install --no-cache-dir colorama capstone transitions

# Home for arbitrary (--user) uids; bind-mounted by the orchestrator so
# pandare's generic image cache (~/.panda) persists between runs
RUN mkdir -p /hy2home && chmod 777 /hy2home
ENV HOME=/hy2home
