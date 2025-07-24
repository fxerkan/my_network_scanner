# Multi-stage Docker build for My Network Scanner (MyNeS)
FROM python:3.11-slim AS base

# Add these ARG definitions before the LABEL statements
ARG BUILD_DATE="unknown"
ARG VERSION="latest"

# Metadata for Docker Hub
LABEL maintainer="fxerkan <fxerkan@gmail.com>"
LABEL description="My Network Scanner (MyNeS) - Your Family's User-Friendly Network Scanner"
LABEL url="https://github.com/fxerkan/my_network_scanner"
LABEL license="MIT"
LABEL homepage="https://github.com/fxerkan/my_network_scanner"
LABEL logo="https://raw.githubusercontent.com/fxerkan/my_network_scanner/refs/heads/main/static/logo.png"
LABEL org.opencontainers.image.title="My Network Scanner (MyNeS)"
LABEL org.opencontainers.image.description="A comprehensive LAN scanner application with web interface, device discovery, and analysis capabilities"
LABEL org.opencontainers.image.authors="fxerkan"
LABEL org.opencontainers.image.url="https://github.com/fxerkan/my_network_scanner"
LABEL org.opencontainers.image.source="https://github.com/fxerkan/my_network_scanner"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.logo="https://raw.githubusercontent.com/fxerkan/my_network_scanner/refs/heads/main/static/logo.png"
LABEL org.opencontainers.image.revision=HEAD
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.documentation="https://raw.githubusercontent.com/fxerkan/my_network_scanner/refs/heads/main/README.md"


# Install system dependencies including build tools
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    net-tools \
    iproute2 \
    curl \
    git \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements-docker.txt requirements.txt ./

# Install Python dependencies (try docker-specific first, fallback to regular)
RUN pip install --no-cache-dir -r requirements-docker.txt || \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p config data static/js static/css templates

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Create non-root user for security
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

# Expose port
EXPOSE 5883

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5883/api/version || exit 1

# Run the application
CMD ["python", "app.py"]