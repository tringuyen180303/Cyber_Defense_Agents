# Isolated CI runner. No network, no host writes: the agent sees what the job would do.
# Override BASE when Docker Hub is unreachable and a local Python image is already present.
ARG BASE=python:3.12-slim-bookworm
FROM ${BASE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash jq findutils \
    && pip install --no-cache-dir pyyaml semgrep \
    && rm -rf /var/lib/apt/lists/*

COPY stubs/ /opt/stubs/
COPY scan.py entrypoint.sh /opt/
RUN chmod 755 /opt/stubs/aws /opt/stubs/npm /opt/stubs/docker /opt/entrypoint.sh /opt/scan.py

ENV PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
ENTRYPOINT ["/opt/entrypoint.sh"]
