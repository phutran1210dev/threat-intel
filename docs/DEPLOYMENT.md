# Deployment Guide

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended) or macOS
- **Memory**: Minimum 8GB RAM (16GB+ recommended for production)
- **Storage**: 50GB+ available disk space
- **CPU**: 4+ cores recommended
- **Network**: Internet connectivity for threat feed access

### Required Software
- Docker 20.10+
- Docker Compose 2.0+
- Python 3.11+
- Git

## Quick Start (Development)

### 1. Clone Repository
```bash
git clone <repository-url>
cd threat-Intelligence-dashboard
```

### 2. Run Setup Script
```bash
./setup.sh
```

The setup script will:
- Check system requirements
- Start Docker containers
- Initialize Elasticsearch indices
- Create sample data
- Verify installation

### 3. Access Services
- **Kibana Dashboard**: http://localhost:5601
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## Production Deployment

### 1. Environment Configuration

Copy and customize the environment file:
```bash
cp .env.example .env
# Edit .env with your production values
```

Key configurations:
```bash
# Production Elasticsearch (if external)
ES_HOST=your-elasticsearch-cluster.com
ES_USERNAME=elastic
ES_PASSWORD=your-secure-password

# Threat Intelligence API Keys
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your-misp-api-key
OTX_API_KEY=your-otx-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
SHODAN_API_KEY=your-shodan-api-key

# Alert Configuration
EMAIL_SMTP_SERVER=smtp.yourcompany.com
EMAIL_USERNAME=alerts@yourcompany.com
EMAIL_PASSWORD=your-email-password
EMAIL_RECIPIENTS=security-team@yourcompany.com

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

### 2. Production Docker Compose

Create `docker-compose.prod.yml`:
```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=${ES_PASSWORD}
      - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    deploy:
      resources:
        limits:
          memory: 6g

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=${ES_PASSWORD}
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

  threat-collector:
    build:
      context: .
      dockerfile: docker/Dockerfile.collector
    environment:
      - ES_HOST=elasticsearch
      - ES_PASSWORD=${ES_PASSWORD}
    depends_on:
      - elasticsearch
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
    restart: unless-stopped

  threat-api:
    build:
      context: .
      dockerfile: docker/Dockerfile.api
    environment:
      - ES_HOST=elasticsearch
      - ES_PASSWORD=${ES_PASSWORD}
    ports:
      - "8000:8000"
    depends_on:
      - elasticsearch
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
    restart: unless-stopped

volumes:
  elasticsearch_data:
```

### 3. Deploy to Production

```bash
# Start production services
docker-compose -f docker-compose.prod.yml up -d

# Initialize production data
python scripts/setup_indices.py

# Verify deployment
curl http://localhost:8000/health
```

## Kubernetes Deployment

### 1. Create Namespace
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: threat-intel
```

### 2. Deploy Elasticsearch
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: elasticsearch
  namespace: threat-intel
spec:
  serviceName: elasticsearch
  replicas: 3
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
      - name: elasticsearch
        image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
        ports:
        - containerPort: 9200
        - containerPort: 9300
        env:
        - name: cluster.name
          value: threat-intel-cluster
        - name: node.name
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: discovery.seed_hosts
          value: "elasticsearch-0.elasticsearch,elasticsearch-1.elasticsearch,elasticsearch-2.elasticsearch"
        - name: cluster.initial_master_nodes
          value: "elasticsearch-0,elasticsearch-1,elasticsearch-2"
        - name: ES_JAVA_OPTS
          value: "-Xms2g -Xmx2g"
        volumeMounts:
        - name: elasticsearch-storage
          mountPath: /usr/share/elasticsearch/data
        resources:
          requests:
            memory: "3Gi"
          limits:
            memory: "4Gi"
  volumeClaimTemplates:
  - metadata:
      name: elasticsearch-storage
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 100Gi
```

### 3. Deploy Application Components
```yaml
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
      - name: threat-api
        image: threat-intel/api:latest
        ports:
        - containerPort: 8000
        env:
        - name: ES_HOST
          value: elasticsearch
        - name: ES_PORT
          value: "9200"
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
  - port: 8000
    targetPort: 8000
  type: LoadBalancer
```

## Cloud Deployment (AWS)

### 1. Infrastructure Setup

Use Terraform or CloudFormation to create:
- VPC with public/private subnets
- EKS cluster or EC2 instances
- RDS for metadata (optional)
- ElastiCache for Redis
- Application Load Balancer
- Security groups and IAM roles

### 2. Amazon Elasticsearch Service
```yaml
# CloudFormation template snippet
ElasticsearchDomain:
  Type: AWS::Elasticsearch::Domain
  Properties:
    DomainName: threat-intel-es
    ElasticsearchVersion: 7.10
    ClusterConfig:
      InstanceType: m5.large.elasticsearch
      InstanceCount: 3
      DedicatedMasterEnabled: true
      MasterInstanceType: m5.medium.elasticsearch
      MasterInstanceCount: 3
    EBSOptions:
      EBSEnabled: true
      VolumeType: gp2
      VolumeSize: 100
    VPCOptions:
      SecurityGroupIds:
        - !Ref ESSecurityGroup
      SubnetIds:
        - !Ref PrivateSubnet1
        - !Ref PrivateSubnet2
```

### 3. EKS Deployment
```bash
# Create EKS cluster
eksctl create cluster --name threat-intel-cluster --region us-east-1

# Deploy application
kubectl apply -f k8s/
```

## Monitoring and Observability

### 1. Prometheus Metrics
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'threat-intel-api'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

### 2. Grafana Dashboards
Import pre-built dashboards:
- Elasticsearch metrics
- Application performance
- Alert statistics
- IOC collection rates

### 3. Log Management
Configure log shipping to ELK stack or cloud logging:
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /app/logs/*.log
  json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

## Security Configuration

### 1. Enable Elasticsearch Security
```yaml
# elasticsearch.yml
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true
```

### 2. Setup SSL/TLS
```bash
# Generate certificates
elasticsearch-certutil ca
elasticsearch-certutil cert --ca elastic-stack-ca.p12
```

### 3. Configure Authentication
```bash
# Setup built-in users
elasticsearch-setup-passwords interactive

# Create API users
curl -X POST "localhost:9200/_security/user/threat-intel-api" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "secure-password",
    "roles": ["threat_intel_writer", "threat_intel_reader"]
  }'
```

## Backup and Recovery

### 1. Elasticsearch Snapshots
```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/threat-intel-backups" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "fs",
    "settings": {
      "location": "/opt/elasticsearch/backups"
    }
  }'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/threat-intel-backups/daily-backup" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": "threat_*",
    "ignore_unavailable": true
  }'
```

### 2. Automated Backups
```bash
#!/bin/bash
# backup-script.sh

DATE=$(date +%Y%m%d_%H%M%S)
SNAPSHOT_NAME="backup_$DATE"

curl -X PUT "localhost:9200/_snapshot/threat-intel-backups/$SNAPSHOT_NAME" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": "threat_*",
    "ignore_unavailable": true
  }'

# Add to cron for daily backups
# 0 2 * * * /path/to/backup-script.sh
```

## Performance Tuning

### 1. Elasticsearch Tuning
```yaml
# elasticsearch.yml
indices.memory.index_buffer_size: 10%
indices.fielddata.cache.size: 20%
thread_pool.write.size: 2
thread_pool.write.queue_size: 1000
```

### 2. Application Tuning
```yaml
# API configuration
workers: 4
max_connections: 1000
keepalive_timeout: 5
worker_connections: 1000
```

### 3. System Tuning
```bash
# Increase file descriptors
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Disable swap for Elasticsearch
swapoff -a
echo "vm.swappiness = 1" >> /etc/sysctl.conf
```

## Troubleshooting

### Common Issues

1. **Elasticsearch cluster red status**
   ```bash
   curl localhost:9200/_cluster/health
   curl localhost:9200/_cat/indices?v
   ```

2. **High memory usage**
   ```bash
   # Check ES heap usage
   curl localhost:9200/_nodes/stats/jvm
   ```

3. **API connection issues**
   ```bash
   # Check API health
   curl localhost:8000/health/detailed
   ```

### Log Analysis
```bash
# Check collector logs
docker logs threat-intel-collector

# Check API logs  
docker logs threat-intel-api

# Check Elasticsearch logs
docker logs threat-intel-elasticsearch
```

This deployment guide provides comprehensive instructions for various deployment scenarios, from development to production environments.