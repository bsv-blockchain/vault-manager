# Docker Deployment Guide

Docker containerization for BSV Vault Manager and Transfer applications.

## Applications

### 🔐 Vault Manager
**Port**: 3000 | **Directory**: `./vault`

Secure offline vault manager for BSV with:
- Hierarchical deterministic key generation
- UTXO management and coin selection
- Transaction creation and signing
- Atomic BEEF format support
- QR code transmission for air-gapped security
- Institutional dark theme UI

### 📱 Transfer App
**Port**: 3001 | **Directory**: `./transfer`

Transaction management with WalletClient integration:
- Send mode: Create transactions with QR scanning
- Receive mode: Generate addresses with BRC-42 derivation
- Animated chunked QR codes for large transactions
- Compatible with Vault Manager for air-gapped transmission
- Matching institutional theme

## Quick Start

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+

### Run Both Apps

```bash
# Build and start both applications
docker-compose up -d

# View logs
docker-compose logs -f

# Stop applications
docker-compose down
```

**Access**:
- Vault Manager: http://localhost:3000
- Transfer App: http://localhost:3001

### Individual App Management

```bash
# Build specific app
docker-compose build vault
docker-compose build transfer

# Start specific app
docker-compose up -d vault
docker-compose up -d transfer

# Restart specific app
docker-compose restart vault

# View app logs
docker-compose logs -f vault
```

### Rebuild After Changes

```bash
# Rebuild and restart
docker-compose up -d --build

# Force rebuild without cache
docker-compose build --no-cache
docker-compose up -d
```

## Docker Architecture

Both apps use multi-stage builds:

1. **Build stage** (Node 20 Alpine):
   - Install dependencies with `npm ci`
   - Compile TypeScript
   - Bundle assets with Vite
   - Optimize for production

2. **Production stage** (Nginx Alpine):
   - Copy built static files
   - Serve with optimized Nginx config
   - Enable gzip compression
   - Add security headers

### Container Details

**Vault Manager Container**:
- Base Image: `nginx:alpine`
- Internal Port: 80
- Exposed Port: 3000
- Network: bsv-network
- Size: ~50MB
- Build Context: `./vault`

**Transfer Container**:
- Base Image: `nginx:alpine`
- Internal Port: 80
- Exposed Port: 3001
- Network: bsv-network
- Size: ~45MB
- Build Context: `./transfer`

## Configuration

### Custom Ports

Edit `docker-compose.yml` to change ports:

```yaml
services:
  vault:
    ports:
      - "8080:80"  # Change 3000 to 8080

  transfer:
    ports:
      - "8081:80"  # Change 3001 to 8081
```

Then restart:
```bash
docker-compose up -d
```

### Nginx Configuration

Custom nginx configs:
- `./vault/nginx.conf`
- `./transfer/nginx.conf`

Features enabled:
- Gzip compression for text assets
- Security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
- SPA routing support (fallback to index.html)
- Static asset caching (1 year for immutable assets)

To modify:
1. Edit the nginx.conf file
2. Rebuild the container: `docker-compose build vault`
3. Restart: `docker-compose up -d vault`

### Environment Variables

None required - both apps are stateless frontends.

### Docker Network

Apps communicate via `bsv-network` bridge network:
```yaml
networks:
  bsv-network:
    driver: bridge
```

## Development vs Production

### Development Mode

Run locally without Docker:

```bash
# Vault Manager
cd vault
npm install
npm run dev  # Port 5173

# Transfer App
cd transfer
npm install
npm run dev  # Port 3001
```

### Production Mode

Use Docker Compose:

```bash
docker-compose up -d
```

Benefits:
- Optimized builds
- Nginx serving (faster, more reliable)
- Easy deployment
- Consistent environments
- Resource isolation

## Usage Workflows

### Air-Gapped Transaction Flow

1. **Create Transaction** (Vault Manager - Offline):
   ```
   Open: http://localhost:3000
   → Load vault file
   → Create outgoing transaction
   → Display as animated QR code
   ```

2. **Transmit via QR**:
   - Use camera to scan QR from offline device
   - Or scan with Transfer App on online device

3. **Process Transaction** (Transfer App - Online):
   ```
   Open: http://localhost:3001
   → Receive mode
   → Scan incoming BEEF QR code
   → Internalize transaction
   → Broadcast to network (if configured)
   ```

### QR Code System

- **Chunking**: Data >100 chars split into 80-char chunks
- **Format**: `CHUNK:id:index:total:data`
- **Animation**: 200ms interval cycling
- **Scanning**: Automatic chunk collection and reassembly

## Troubleshooting

### Port Conflicts

Check if ports are in use:
```bash
# macOS/Linux
lsof -i :3000
lsof -i :3001

# Windows
netstat -ano | findstr :3000
netstat -ano | findstr :3001
```

Solutions:
- Stop conflicting services
- Change ports in `docker-compose.yml`

### Build Failures

```bash
# Clean rebuild
docker-compose down
docker system prune -a --volumes  # WARNING: Removes all unused Docker data
docker-compose build --no-cache
docker-compose up -d
```

### Container Won't Start

Check logs:
```bash
docker-compose logs vault
docker-compose logs transfer
```

Common issues:
- Port already in use
- Out of disk space
- Nginx config syntax error

### Camera Not Working (QR Scanning)

Requirements:
- HTTPS connection OR localhost
- Camera permissions granted in browser
- No other apps using camera
- Modern browser (Chrome, Firefox, Safari, Edge)

Test camera access:
```javascript
// In browser console
navigator.mediaDevices.getUserMedia({ video: true })
  .then(stream => console.log('Camera OK'))
  .catch(err => console.error('Camera error:', err))
```

### Slow Build Times

Speed up builds:
```bash
# Use buildkit
COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker-compose build

# Or export permanently
export COMPOSE_DOCKER_CLI_BUILD=1
export DOCKER_BUILDKIT=1
```

## Maintenance

### Update Dependencies

```bash
# Update npm packages (do this outside Docker)
cd vault
npm update
npm audit fix

cd ../transfer
npm update
npm audit fix

# Rebuild containers
docker-compose build --no-cache
docker-compose up -d
```

### View Resource Usage

```bash
# See resource consumption
docker stats

# Container sizes
docker-compose images
```

### Cleanup

```bash
# Stop and remove containers
docker-compose down

# Remove containers and volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Full cleanup
docker system prune -a
```

## Security Considerations

⚠️ **Important**:

1. **Vault Manager**:
   - Designed for offline/air-gapped use
   - Do NOT expose to internet
   - Run on dedicated secure machine
   - Follow operational manual procedures

2. **Transfer App**:
   - Requires WalletInterface integration
   - Review all wallet interactions
   - Use HTTPS in production
   - Implement proper authentication if exposing publicly

3. **Vault Files**:
   - Always verify SHA-256 hashes
   - Store encrypted with strong passwords
   - Keep multiple backups
   - Test recovery procedures

4. **Docker Security**:
   - Keep Docker Engine updated
   - Use specific image versions (not `latest`)
   - Scan images for vulnerabilities
   - Limit container resources if needed

5. **QR Codes**:
   - Visual transmission can be recorded
   - Use in private/secure locations
   - Verify transaction details before processing

## Production Deployment

### Recommended Setup

```yaml
services:
  vault:
    build: ./vault
    restart: always
    ports:
      - "127.0.0.1:3000:80"  # Bind to localhost only
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M

  transfer:
    build: ./transfer
    restart: always
    ports:
      - "0.0.0.0:3001:80"  # Publicly accessible
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
```

### With Reverse Proxy (Recommended)

Use nginx or traefik as reverse proxy:

```nginx
# Example nginx config
server {
    listen 443 ssl http2;
    server_name vault.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Monitoring

### Health Checks

Add to `docker-compose.yml`:

```yaml
services:
  vault:
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### Logging

View logs:
```bash
# Follow all logs
docker-compose logs -f

# Last 100 lines
docker-compose logs --tail=100

# Specific service
docker-compose logs -f vault
```

Export logs:
```bash
docker-compose logs > app-logs.txt
```

## Support

For issues or questions:
- Check troubleshooting section above
- Review container logs
- Verify Docker and Docker Compose versions
- Test without Docker to isolate issues
- Create GitHub issue with details

## License

Same as parent project (Open BSV / ISC)
