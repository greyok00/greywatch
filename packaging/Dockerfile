# packaging/Dockerfile — the container the release workflow pushes to
# ghcr.io (GitHub's Packages registry). GitHub Packages has no pip/Debian
# type, so the container is the package the Packages tab lists.
#
#   docker build -f packaging/Dockerfile -t ghcr.io/greyok00/greywatch:local .
#
# The layout and the run-by-path semantics are the Debian package's:
# /opt/greywatch holds the whole program tree, and `gw` runs
# /opt/greywatch/cli.py by path. The tree is compiled INSIDE the image
# (requirements-build.txt pins say which Cython), so the .so always
# matches the image's own interpreter no matter the build host.
FROM docker.io/library/ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-dev python3-pip build-essential \
      python3-gi python3-gi-cairo gir1.2-gtk-4.0 yara && \
    rm -rf /var/lib/apt/lists/*

ARG GW_VERSION=dev
WORKDIR /opt/greywatch
COPY . .

RUN python3 -m venv --system-site-packages .venv && \
    .venv/bin/pip install --no-cache-dir \
      -r requirements-dev.txt -r requirements-build.txt
RUN . .venv/bin/activate && ./build-cython.sh
# smoke: the compiled tree answers before the image is accepted
RUN .venv/bin/python /opt/greywatch/cli.py --version
RUN rm -rf build .pytest_cache .ruff_cache tmp* && \
    find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

RUN printf '#!/bin/sh\nexec /opt/greywatch/.venv/bin/python /opt/greywatch/cli.py "$@"\n' \
    > /usr/local/bin/gw && chmod 0755 /usr/local/bin/gw

LABEL org.opencontainers.image.title=greywatch \
      org.opencontainers.image.description="One dashboard for every protection on a Linux machine" \
      org.opencontainers.image.source=https://github.com/greyok00/greywatch \
      org.opencontainers.image.licenses=Apache-2.0 \
      org.opencontainers.image.version=$GW_VERSION

ENTRYPOINT ["/usr/local/bin/gw"]
CMD ["--help"]