# packaging/Dockerfile — the container the release workflow pushes to
# ghcr.io (GitHub's Packages registry). GitHub Packages has no pip/Debian
# type, so the container is the package the Packages tab lists.
#
#   docker build -f packaging/Dockerfile -t ghcr.io/greyok00/greywatch:local .
#
# The layout and the run-by-path semantics are the Debian package's:
# /opt/greywatch holds the whole program tree, and `gw` runs
# /opt/greywatch/cli.py by path. The tree ships plain readable Python
# (owner law 2026-11-10): nothing is compiled in the image — the image's
# own python3 runs it, so a venv would be dead weight. The one runtime
# compile is the C NFQUEUE verdict worker (appfw/nfq_worker.c built by
# gcc at first arm, appfw/engine.py), so its build deps ride along.
FROM docker.io/library/ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 build-essential gcc libnetfilter-queue-dev \
      libnetfilter-queue1 python3-gi python3-gi-cairo gir1.2-gtk-4.0 \
      yara && \
    rm -rf /var/lib/apt/lists/*

ARG GW_VERSION=dev
WORKDIR /opt/greywatch
COPY . .

# smoke: the tree answers before the image is accepted
RUN /usr/bin/python3 /opt/greywatch/cli.py --version
RUN rm -rf build .pytest_cache .ruff_cache tmp* && \
    find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

RUN printf '#!/bin/sh\nexec /usr/bin/python3 /opt/greywatch/cli.py "$@"\n' \
    > /usr/local/bin/gw && chmod 0755 /usr/local/bin/gw

LABEL org.opencontainers.image.title=greywatch \
      org.opencontainers.image.description="One dashboard for every protection on a Linux machine" \
      org.opencontainers.image.source=https://github.com/greyok00/greywatch \
      org.opencontainers.image.licenses=Apache-2.0 \
      org.opencontainers.image.version=$GW_VERSION

ENTRYPOINT ["/usr/local/bin/gw"]
CMD ["--help"]