# Docker Troubleshooting Guide for My Network Scanner

This guide helps diagnose and fix common issues when running My Network Scanner in Docker containers.

## Common Issues and Solutions

### 1. Application Not Accessible (Connection Refused)

**Symptoms:**
- `curl: (7) Failed to connect to localhost port 5883: Connection refused`
- Web browser shows "This site can't be reached"
- Docker container appears to be running but app is not accessible

**Causes & Solutions:**

#### A. Port Binding Issues
```bash
# Check if port is properly mapped
docker port my-network-scanner
# Should show: 5883/tcp -> 0.0.0.0:5883

# If not, recreate container with correct port mapping
docker run -d --name my-network-scanner -p 5883:5883 fxerkan/my_network_scanner:latest
```

#### B. Flask Not Binding to All Interfaces
The app should bind to `0.0.0.0:5883`, not `127.0.0.1:5883`.

**Check logs:**
```bash
docker logs my-network-scanner
# Look for: "🌍 Host: 0.0.0.0 (all interfaces)"
```

#### C. Debug Mode Issues in Production
**Check environment variables:**
```bash
docker exec my-network-scanner env | grep FLASK
# Should show: FLASK_ENV=production
```

### 2. Network Scanning Not Working

**Symptoms:**
- No devices found in scans
- "Network interfaces not available" errors
- Permission denied errors for nmap

**Solutions:**

#### A. Missing Privileged Mode
```bash
# Recreate with privileged mode
docker run -d --privileged --name my-network-scanner \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -p 5883:5883 fxerkan/my_network_scanner:latest
```

#### B. Network Interface Detection Issues
```bash
# Test network interface detection
docker exec my-network-scanner python3 -c "
from network_utils import get_network_interfaces, is_docker_environment
print(f'Docker: {is_docker_environment()}')
print(f'Interfaces: {len(get_network_interfaces())}')
"
```

### 3. Container Starts But App Crashes

**Symptoms:**
- Container exits immediately
- Health check fails
- Application errors in logs

**Diagnosis:**
```bash
# Check container logs
docker logs my-network-scanner

# Check health status
docker inspect my-network-scanner | grep -A 5 '"Health"'

# Run health check manually
docker exec my-network-scanner python3 docker-healthcheck.py
```

**Common Fixes:**
- Ensure all dependencies are installed
- Check file permissions
- Verify environment variables

### 4. Port Conflicts

**Symptoms:**
- `bind: address already in use`
- Port 5883 already occupied

**Solutions:**
```bash
# Find what's using the port
sudo lsof -i :5883

# Use different host port
docker run -p 8883:5883 fxerkan/my_network_scanner:latest

# Or stop conflicting service
sudo systemctl stop <service-name>
```

### 5. Volume Mount Issues

**Symptoms:**
- Configuration not persisted
- Permission denied on data files
- Files not accessible

**Solutions:**
```bash
# Check volume mounts
docker inspect my-network-scanner | grep -A 10 '"Mounts"'

# Fix permissions
sudo chown -R 1000:1000 ./data ./config

# Recreate with proper volumes
docker run -d \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  fxerkan/my_network_scanner:latest
```

## Diagnostic Commands

### Quick Health Check
```bash
# Run comprehensive health check
docker exec my-network-scanner python3 docker-healthcheck.py
```

### Network Diagnostics
```bash
# Check network configuration
docker exec my-network-scanner ip addr show
docker exec my-network-scanner ip route show

# Test connectivity
docker exec my-network-scanner ping -c 3 8.8.8.8
docker exec my-network-scanner nmap -V
```

### Application Diagnostics
```bash
# Check Flask app status
curl -f http://localhost:5883/api/version

# Check application logs
docker logs -f my-network-scanner

# Check processes inside container
docker exec my-network-scanner ps aux
```

### Environment Check
```bash
# Check environment variables
docker exec my-network-scanner env | grep -E "(FLASK|LAN_SCANNER)"

# Check file permissions
docker exec my-network-scanner ls -la /app/
docker exec my-network-scanner ls -la /app/data/
```

## Docker Compose Troubleshooting

### Service Won't Start
```bash
# Check compose logs
docker-compose logs my-network-scanner

# Validate compose file
docker-compose config

# Recreate services
docker-compose down
docker-compose up -d
```

### Build Issues
```bash
# Force rebuild
docker-compose build --no-cache

# Check build context
docker-compose build --progress=plain
```

## Performance Issues

### Slow Scanning
- Ensure privileged mode is enabled
- Check network latency: `docker exec container ping gateway`
- Verify CPU/memory limits: `docker stats`

### High Resource Usage
```bash
# Monitor resource usage
docker stats my-network-scanner

# Check for memory leaks
docker exec my-network-scanner ps aux --sort=-%mem
```

## Recovery Procedures

### Complete Reset
```bash
# Stop and remove container
docker stop my-network-scanner
docker rm my-network-scanner

# Remove image (optional)
docker rmi fxerkan/my_network_scanner:latest

# Fresh start
docker-compose up -d
```

### Data Recovery
```bash
# Backup current data
docker cp my-network-scanner:/app/data ./backup-data

# Restore data
docker cp ./backup-data/. my-network-scanner:/app/data/
```

## Getting Help

If issues persist:

1. **Collect Information:**
   ```bash
   # System info
   docker version
   docker-compose version
   uname -a
   
   # Container info
   docker logs my-network-scanner > container.log
   docker inspect my-network-scanner > container-inspect.json
   ```

2. **Test in Debug Mode:**
   ```bash
   docker run -it --rm -p 5883:5883 \
     -e FLASK_ENV=development \
     fxerkan/my_network_scanner:latest
   ```

3. **Create Issue:** Include logs and system information when reporting issues.

## Prevention

- Always use `docker-compose.yml` for consistent deployments
- Regularly update to latest image version
- Monitor container health and logs
- Backup configuration and data regularly
- Test deployments in staging environment first