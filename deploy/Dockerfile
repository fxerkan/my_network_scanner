# Docker image for My Network Scanner (MyNeS)
# Build from the repo root:  docker build -f deploy/Dockerfile .
FROM python:3.12-slim

ARG BUILD_DATE="unknown"
ARG VERSION="latest"

LABEL maintainer="fxerkan <fxerkan@gmail.com>"
LABEL org.opencontainers.image.title="My Network Scanner (MyNeS)"
LABEL org.opencontainers.image.description="Home-lab network discovery, monitoring and Home Assistant integration"
LABEL org.opencontainers.image.authors="fxerkan"
LABEL org.opencontainers.image.url="https://github.com/fxerkan/my_network_scanner"
LABEL org.opencontainers.image.source="https://github.com/fxerkan/my_network_scanner"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.documentation="https://github.com/fxerkan/my_network_scanner#readme"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.version="${VERSION}"

# perl-base carries 2 CRITICAL + 2 HIGH CVEs that Debian has no fix for, and
# nothing here runs perl - nmap's NSE is Lua. Its only dependant is debconf,
# which only matters to apt, and apt is finished by the end of this layer.
# --force-depends leaves debconf installed but broken; that is the whole cost:
# the image can no longer apt-get install. See README, "İmajda apt yok".
# gosu is gone too: its Go stdlib carried 39 CVEs and setpriv (util-linux, part
# of the base image) does the same drop-to-user job. See entrypoint.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iputils-ping net-tools iproute2 avahi-utils \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && dpkg --force-remove-essential --force-depends --purge perl-base \
    && rm -rf /usr/share/perl /usr/share/perl5 /usr/bin/perl*

WORKDIR /app

COPY deploy/requirements-docker.txt requirements.txt ./
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY pyproject.toml README.md LICENSE ./
COPY mynes ./mynes
COPY config ./config

# Not editable: an editable install needs pip's machinery to stay behind, and
# pip/setuptools/wheel are 5 more CVEs for something nothing runs at runtime.
RUN pip install --no-cache-dir --no-deps . && mkdir -p /app/data \
    && pip uninstall -y pip setuptools wheel

ENV PYTHONUNBUFFERED=1 \
    MYNES_HOME=/app \
    MYNES_PORT=5883

RUN useradd -m -u 1000 scanner && chown -R scanner:scanner /app

# cap_add: NET_RAW/NET_ADMIN alone does nothing for a non-root process - the
# caps land in the bounding set, never the effective one, so raw ARP silently
# fell back to a ping sweep on every container install. File capabilities on
# the interpreter survive the switch to `scanner`; without cap_add they are
# still inert, so this grants nothing the operator did not ask for.
RUN setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v python3)")"

COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5883

# python, not curl: curl dragged in libcurl/openldap/krb5/gnutls and 15 CVEs for
# one HTTP GET. http.client rather than urllib because urlopen raises on 401 and
# /api/version returns 401 once auth is on - that read 'unhealthy' forever. Any
# reply below 500 means the server is up, which is all a healthcheck should ask.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import http.client as h; c=h.HTTPConnection('localhost',5883,timeout=5); c.request('GET','/api/version'); exit(0 if c.getresponse().status < 500 else 1)" || exit 1

# Starts as root only to join the docker socket's group, then drops to
# `scanner` for the application itself. See entrypoint.sh.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "-m", "mynes"]
