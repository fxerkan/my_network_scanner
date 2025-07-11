# Docker Deployment Guide for My Network Scanner (MyNeS)

This guide provides comprehensive instructions for deploying MyNeS using Docker, including containerization, Docker Hub publishing, and GitHub Actions automation.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Setup](#docker-setup)
3. [Docker Compose](#docker-compose)
4. [Environment Variables](#environment-variables)
5. [Docker Hub Publishing](#docker-hub-publishing)
6. [GitHub Actions CI/CD](#github-actions-cicd)
7. [Production Deployment](#production-deployment)
8. [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+
- Git

### 1. Clone and Build

```bash
git clone https://github.com/fxerkan/my_network_scanner.git
cd my-network-scanner

# Build the Docker image
docker build -t my-network-scanner:latest .
```

### 2. Run with Docker Compose

```bash
# Set master password (optional)
export LAN_SCANNER_PASSWORD="your-secure-password"

# Start the application
docker-compose up -d

# View logs
docker-compose logs -f
```

### 3. Access the Application

Open your browser and navigate to:

- **Development**: http://localhost:5883
- **Production** (with nginx): http://localhost

## Docker Setup

### Dockerfile Features

- **Multi-stage build** for optimized image size
- **Security-focused** with non-root user
- **Health checks** for container monitoring
- **System dependencies** for network scanning (nmap, ping, etc.)

### Key Components

- **Base Image**: Python 3.11 slim
- **Network Tools**: nmap, iputils-ping, net-tools
- **User**: Non-root user `scanner` (UID 1000)
- **Port**: 5883 (Flask application)
- **Health Check**: `/api/version` endpoint

## Docker Compose

### Services

#### 1. Main Application (`my-network-scanner`)

```yaml
services:
  my-network-scanner:
    build: .
    image: fxerkan/my_network_scanner:latest
    container_name: my-network-scanner
    ports:
      - "5883:5883"
    volumes:
      - ./data:/app/data      # Persistent scan data
      - ./config:/app/config  # Configuration files
    # Use bridge network with privileged mode for scanning
    cap_add:
      - NET_ADMIN
      - NET_RAW
    network_mode: host        # Required for network scanning
    privileged: true          # Required for nmap
```

#### 2. Nginx Reverse Proxy (Optional)

```yaml
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    profiles:
      - production
```

### Volume Mapping

- `./data` → `/app/data`: Scan results and device information
- `./config` → `/app/config`: Application configuration and credentials

## Environment Variables

### Required

```bash
# Master password for credential encryption
export LAN_SCANNER_PASSWORD="your-secure-password"
```

### Optional

```bash
# Flask environment
export FLASK_ENV=production

# Custom port (default: 5883)
export FLASK_PORT=5883

# Debug mode (development only)
export FLASK_DEBUG=false
```

### Docker Compose Environment File

Create `.env` file in project root:

```env
# Master password for credential storage
LAN_SCANNER_PASSWORD=your-secure-password

# Application settings
FLASK_ENV=production
FLASK_PORT=5883

```

## Docker Hub Publishing

### 1. Prepare for Publishing

```bash
# Login to Docker Hub
docker login

# Build multi-architecture image
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 -t fxerkan/my_network_scanner:latest .
```

### 2. Tagging Strategy

```bash
# Version tagging
docker tag my-network-scanner:latest fxerkan/my_network_scanner:v1.0.0
docker tag my-network-scanner:latest fxerkan/my_network_scanner:latest

# Development builds
docker tag my-network-scanner:latest fxerkan/my_network_scanner:dev
```

### 3. Push to Docker Hub

```bash
# Push specific version
docker push fxerkan/my_network_scanner:v1.0.0

# Push latest
docker push fxerkan/my_network_scanner:latest

# Push all tags
docker push --all-tags fxerkan/my_network_scanner
```

### 4. Multi-Architecture Build and Push

```bash
# Build and push for multiple architectures
docker buildx build --platform linux/amd64,linux/arm64 \
  -t fxerkan/my_network_scanner:latest \
  -t fxerkan/my_network_scanner:v1.0.0 \
  --push .
```

## GitHub Actions CI/CD

### 1. Create GitHub Secrets

In your GitHub repository, go to Settings → Secrets and add:

- `DOCKER_HUB_USERNAME`: Your Docker Hub username
- `DOCKER_HUB_ACCESS_TOKEN`: Docker Hub access token

### 2. GitHub Actions Workflow

Create `.github/workflows/docker-publish.yml`:

```yaml
name: Build and Publish Docker Image

on:
  push:
    branches: [ main, develop ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: docker.io
  IMAGE_NAME: fxerkan/my_network_scanner

jobs:
  build-and-push:
    runs-on: ubuntu-latest
  
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
  
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
  
    - name: Login to Docker Hub
      if: github.event_name != 'pull_request'
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ secrets.DOCKER_HUB_USERNAME }}
        password: ${{ secrets.DOCKER_HUB_ACCESS_TOKEN }}
  
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
          type=raw,value=latest,enable={{is_default_branch}}
    
    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        platforms: linux/amd64,linux/arm64
        push: ${{ github.event_name != 'pull_request' }}
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
```

### 3. Release Workflow

Create `.github/workflows/release.yml`:

```yaml
name: Create Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
  
    steps:
    - name: Checkout
      uses: actions/checkout@v4
  
    - name: Create Release
      uses: actions/create-release@v1
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      with:
        tag_name: ${{ github.ref }}
        release_name: Release ${{ github.ref }}
        draft: false
        prerelease: false
```

## Production Deployment

### 1. Server Setup

```bash
# Install Docker on your server
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 2. Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
services:
  my-network-scanner:
    image: fxerkan/my_network_scanner:latest
    container_name: my-network-scanner
    ports:
      - "5883:5883"
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    environment:
      - FLASK_ENV=production
      - LAN_SCANNER_PASSWORD=${LAN_SCANNER_PASSWORD}
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    privileged: true
  
  nginx:
    image: nginx:alpine
    container_name: my-network-scanner-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - my-network-scanner
    restart: unless-stopped
```

### 3. Nginx Configuration

Create `nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream app {
        server localhost:5883;
    }
  
    server {
        listen 80;
        server_name your-domain.com;
  
        location / {
            proxy_pass http://app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

### 4. SSL Setup with Let's Encrypt

```bash
# Install Certbot
sudo apt install certbot

# Get SSL certificate
sudo certbot certonly --standalone -d your-domain.com

# Update nginx.conf for SSL
```

### 5. Deployment Script

Create `deploy.sh`:

```bash
#!/bin/bash

set -e

# Configuration
IMAGE_NAME="fxerkan/my_network_scanner"
CONTAINER_NAME="my-network-scanner"

echo "🚀 Deploying My Network Scanner..."

# Pull latest image
echo "📦 Pulling latest image..."
docker pull $IMAGE_NAME:latest

# Stop and remove existing container
echo "⏹️ Stopping existing container..."
docker-compose -f docker-compose.prod.yml down

# Start new container
echo "▶️ Starting new container..."
docker-compose -f docker-compose.prod.yml up -d

# Wait for health check
echo "🔍 Waiting for application to be healthy..."
timeout 60 bash -c 'while [[ "$(docker inspect --format=\"{{.State.Health.Status}}\" $CONTAINER_NAME)" != "healthy" ]]; do sleep 2; done'

echo "✅ Deployment completed successfully!"
echo "🌐 Application available at: http://localhost:5883"
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied for Network Scanning

**Error**: `Permission denied` when scanning network

**Solution**:

```bash
# Ensure privileged mode is enabled
docker run --privileged --network host fxerkan/my_network_scanner:latest

# Or add specific capabilities
docker run --cap-add=NET_ADMIN --cap-add=NET_RAW fxerkan/my_network_scanner:latest
```

#### 2. Cannot Access Host Network

**Error**: Cannot scan host network interfaces

**Solution**:

```bash
# Use host network mode
docker run --network host fxerkan/my_network_scanner:latest
```

#### 3. Port Already in Use

**Error**: `Port 5883 is already in use`

**Solution**:

```bash
# Check what's using the port
sudo lsof -i :5883

# Use different port
docker run -p 5004:5883 fxerkan/my_network_scanner:latest
```

#### 4. Container Exits Immediately

**Error**: Container starts but exits immediately

**Solution**:

```bash
# Check container logs
docker logs my-network-scanner

# Run interactively for debugging
docker run -it fxerkan/my_network_scanner:latest /bin/bash
```

### Health Checks

```bash
# Check container health
docker inspect my-network-scanner | grep -A 10 Health

# Manual health check
curl -f http://localhost:5883/api/version

# View container logs
docker logs -f my-network-scanner
```

### Performance Tuning

#### 1. Memory Limits

```yaml
services:
  my-network-scanner:
    mem_limit: 512m
    memswap_limit: 512m
```

#### 2. CPU Limits

```yaml
services:
  my-network-scanner:
    cpus: '0.5'
```

#### 3. Restart Policies

```yaml
services:
  my-network-scanner:
    restart: unless-stopped
    # or: restart: on-failure:3
```

## Security Considerations

### 1. Network Security

- **Host Network Mode**: Required for network scanning but exposes all ports
- **Firewall Rules**: Configure iptables to restrict access
- **VPN Access**: Consider VPN-only access for production

### 2. Container Security

- **Non-root User**: Application runs as user `scanner` (UID 1000)
- **Read-only Filesystem**: Mount application as read-only where possible
- **Secrets Management**: Use Docker secrets for sensitive data

### 3. Data Protection

- **Volume Encryption**: Encrypt persistent volumes in production
- **Backup Strategy**: Regular backups of configuration and data
- **Access Control**: Restrict container access to authorized users

## Monitoring

### 1. Container Metrics

```bash
# Resource usage
docker stats my-network-scanner

# Container events
docker events --filter container=my-network-scanner
```

### 2. Application Logs

```bash
# Follow logs
docker logs -f my-network-scanner

# Log rotation
docker run --log-driver=json-file --log-opt max-size=10m --log-opt max-file=3
```

### 3. Health Monitoring

```bash
# Set up health check alerts
docker run -d --health-cmd="curl -f http://localhost:5883/api/version" \
           --health-interval=30s \
           --health-timeout=10s \
           --health-retries=3 \
           fxerkan/my_network_scanner:latest
```

---

## Summary

This deployment guide covers:

✅ **Docker containerization** with optimized Dockerfile
✅ **Docker Compose** setup for easy deployment
✅ **GitHub Actions** for automated CI/CD
✅ **Docker Hub publishing** with multi-architecture support
✅ **Production deployment** with nginx reverse proxy
✅ **Security best practices** and troubleshooting guide

For additional help, please refer to the [main documentation](README.md) or open an issue on GitHub.
