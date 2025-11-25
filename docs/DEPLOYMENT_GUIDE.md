# 🚀 Deployment Guide

This guide covers different deployment scenarios for the Threat Intelligence Dashboard.

## 📋 Prerequisites

### System Requirements
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 50GB+ SSD storage
- **Network**: Outbound internet access for threat feeds

### Software Requirements
- **Docker**: 20.10+ with Docker Compose
- **Operating System**: Linux (Ubuntu/CentOS), macOS, or Windows with WSL2
- **Available Ports**: 5601 (Kibana), 8000 (API), 9200 (Elasticsearch)

## 🏃 Quick Development Setup

```bash
# Clone repository
git clone <repository-url>
cd threat-Intelligence-dashboard

# Start all services
docker-compose up -d

# Verify deployment
curl http://localhost:8000/health
```

## 🏢 Production Deployment

### 1. Environment Configuration

Create production `.env` file:
```bash
# Production Environment
NODE_ENV=production
LOG_LEVEL=INFO

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# Elasticsearch Configuration
ELASTICSEARCH_URL=https://es-cluster.internal:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=your-secure-password

# Security
API_SECRET_KEY=your-256-bit-secret-key
JWT_SECRET=your-jwt-secret-key

# External Services
VIRUSTOTAL_API_KEY=your-virustotal-key
MISP_API_KEY=your-misp-api-key
OTX_API_KEY=your-otx-api-key

# Monitoring
ENABLE_METRICS=true
SENTRY_DSN=your-sentry-dsn
```

### 2. Security Hardening

#### SSL/TLS Configuration
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  api:
    environment:
      - SSL_KEYFILE=/certs/server.key
      - SSL_CERTFILE=/certs/server.crt
    volumes:
      - ./certs:/certs:ro
    ports:
      - "443:8000"
```

#### Network Security
```yaml
networks:
  internal:
    driver: bridge
    internal: true
  external:
    driver: bridge
```

### 3. Elasticsearch Security

Enable security in `config/elasticsearch/elasticsearch.yml`:
```yaml
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true

# Authentication
xpack.security.authc:
  realms:
    native:
      native1:
        order: 0
```

### 4. Load Balancer Configuration

#### NGINX Configuration
```nginx
upstream threat_api {
    server api1:8000;
    server api2:8000;
    server api3:8000;
}

server {
    listen 80;
    server_name threat-intel.yourdomain.com;
    
    location / {
        proxy_pass http://threat_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🐳 Container Orchestration

### Docker Swarm Deployment

```yaml
# docker-stack.yml
version: '3.8'
services:
  api:
    image: threat-intel/api:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
    networks:
      - threat-net
      
  elasticsearch:
    image: elasticsearch:8.11.0
    deploy:
      replicas: 3
      placement:
        constraints:
          - node.role == worker
    volumes:
      - es-data:/usr/share/elasticsearch/data
    networks:
      - threat-net

networks:
  threat-net:
    driver: overlay
    
volumes:
  es-data:
    driver: local
```

Deploy with:
```bash
docker stack deploy -c docker-stack.yml threat-intel
```

### Kubernetes Deployment

#### Namespace and ConfigMap
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: threat-intel

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: threat-config
  namespace: threat-intel
data:
  ELASTICSEARCH_URL: "http://elasticsearch:9200"
  REDIS_URL: "redis://redis:6379"
```

#### API Deployment
```yaml
# k8s/api-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threat-api
  namespace: threat-intel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: threat-api
  template:
    metadata:
      labels:
        app: threat-api
    spec:
      containers:
      - name: api
        image: threat-intel/api:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: threat-config
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: threat-api-service
  namespace: threat-intel
spec:
  selector:
    app: threat-api
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

## 📊 Monitoring Setup

### Health Check Endpoints
```bash
# API Health
curl http://localhost:8000/health

# Elasticsearch Health
curl http://localhost:9200/_cluster/health

# Redis Health
docker exec redis redis-cli ping
```

### Prometheus Metrics
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'threat-api'
    static_configs:
      - targets: ['api:8000']
    metrics_path: '/metrics'
    
  - job_name: 'elasticsearch'
    static_configs:
      - targets: ['elasticsearch:9200']
```

### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Threat Intelligence Dashboard",
    "panels": [
      {
        "title": "API Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "http_request_duration_seconds"
          }
        ]
      }
    ]
  }
}
```

## 🔄 Backup and Recovery

### Elasticsearch Snapshots
```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/threat_backups" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/backup/elasticsearch"
  }
}'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/threat_backups/snapshot_1"
```

### Database Backup Script
```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/threat-intel/$DATE"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup Elasticsearch
curl -X PUT "localhost:9200/_snapshot/threat_backups/backup_$DATE"

# Backup configurations
cp -r config/ $BACKUP_DIR/
cp .env $BACKUP_DIR/

# Compress backup
tar -czf "/backup/threat-intel-$DATE.tar.gz" $BACKUP_DIR
```

## 🚨 Troubleshooting

### Common Issues

#### Elasticsearch Out of Memory
```yaml
# Increase JVM heap size
environment:
  - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
```

#### API Connection Issues
```bash
# Check network connectivity
docker exec api ping elasticsearch
docker exec api ping redis

# Check logs
docker-compose logs api
docker-compose logs elasticsearch
```

#### Performance Issues
```bash
# Monitor resource usage
docker stats

# Check Elasticsearch indices
curl http://localhost:9200/_cat/indices?v

# Monitor Redis memory
docker exec redis redis-cli info memory
```

### Log Analysis
```bash
# API logs
docker-compose logs -f api | grep ERROR

# Elasticsearch logs
docker-compose logs -f elasticsearch | grep WARN

# System resource monitoring
docker exec api top
docker exec elasticsearch ps aux
```

## 🔧 Maintenance

### Regular Tasks

#### Daily
- Check service health status
- Monitor disk space usage
- Review error logs

#### Weekly
- Update threat intelligence feeds
- Clean up old log files
- Review security alerts

#### Monthly
- Update container images
- Backup configuration files
- Performance optimization review

### Update Procedure
```bash
# 1. Backup current state
./scripts/backup.sh

# 2. Pull latest images
docker-compose pull

# 3. Rolling update
docker-compose up -d --no-deps api
docker-compose up -d --no-deps collector
docker-compose up -d --no-deps worker

# 4. Verify services
curl http://localhost:8000/health
```

## 📝 Performance Tuning

### Elasticsearch Optimization
```yaml
# elasticsearch.yml
indices.memory.index_buffer_size: 20%
indices.queries.cache.size: 20%
thread_pool.write.queue_size: 1000
```

### API Server Tuning
```python
# Increase worker processes
workers = multiprocessing.cpu_count() * 2 + 1

# Connection pooling
max_connections = 100
pool_size = 20
```

### Redis Configuration
```conf
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
```

This deployment guide covers development, production, and enterprise deployment scenarios. Choose the approach that best fits your infrastructure and security requirements.