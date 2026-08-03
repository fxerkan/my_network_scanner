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

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iputils-ping net-tools iproute2 curl avahi-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY deploy/requirements-docker.txt requirements.txt ./
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY pyproject.toml README.md LICENSE ./
COPY mynes ./mynes
COPY config ./config

RUN pip install --no-cache-dir --no-deps -e . && mkdir -p /app/data

ENV PYTHONUNBUFFERED=1 \
    MYNES_HOME=/app \
    MYNES_PORT=5883

RUN useradd -m -u 1000 scanner && chown -R scanner:scanner /app
USER scanner

EXPOSE 5883

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5883/api/version || exit 1

CMD ["python", "-m", "mynes"]
