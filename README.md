# 🔍 Threat Intelligence Dashboard

A comprehensive real-time threat intelligence aggregation and visualization platform with IOC tracking, threat actor profiling, and automated alert generation.

![Python](https://img.shields.io/badge/python-v3.11+-blue.svg)
![Elasticsearch](https://img.shields.io/badge/elasticsearch-8.11+-yellow.svg)
![Kibana](https://img.shields.io/badge/kibana-8.11+-purple.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🚀 Features

### Core Capabilities
- **🔄 Real-time IOC Collection**: Automated gathering from 15+ threat intelligence sources
- **🔍 Advanced Search & Analytics**: Elasticsearch-powered full-text search and correlation
- **📊 Interactive Dashboards**: Kibana visualizations with geographic mapping
- **🎯 Threat Actor Profiling**: Advanced analytics for attribution and campaign tracking
- **🚨 Intelligent Alerting**: Multi-channel notifications with risk scoring
- **🔌 Extensible API**: RESTful API with OpenAPI/Swagger documentation

### Supported Threat Intelligence Sources
- **MISP** (Malware Information Sharing Platform)
- **AlienVault OTX** (Open Threat Exchange)  
- **VirusTotal** API integration
- **Shodan** network scanning data
- **Custom RSS/XML** feeds
- **STIX/TAXII** protocols
- **Custom feeds** (extensible architecture)

### IOC Types Supported
- 🌐 IP Addresses (IPv4/IPv6)
- 🏷️ Domain Names & URLs
- 📧 Email Addresses
- 🔒 File Hashes (MD5, SHA1, SHA256, SHA512)
- 🔑 Registry Keys & Mutexes
- 📜 Network Signatures
- 🔖 User Agents & Certificates

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │───▶│   FastAPI        │───▶│  Elasticsearch  │
│   Dashboard     │    │   REST API       │    │   Data Store    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        ▲
                                ▼                        │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│    Kibana       │    │     Redis        │    │     Celery      │
│ Visualization   │    │    Cache &       │    │    Workers      │
│   Dashboard     │    │   Message Bus    │    │  (Background)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         ▲
                                                         │
                                ┌─────────────────────────────┐
                                │   Threat Intel Collector    │
                                │   (MISP, OTX, VirusTotal)   │
                                └─────────────────────────────┘
```

### Components
- **FastAPI**: REST API server with async support
- **Elasticsearch**: Search engine and data store
- **Kibana**: Interactive visualization dashboards
- **Redis**: Caching and message broker
- **Celery**: Distributed task processing
- **Collector**: Automated threat intelligence gathering

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 8GB+ RAM recommended
- Ports 5601, 8000, 9200 available

### Launch the Complete System

1. **Clone and Start**:
   ```bash
   git clone <repository>
   cd threat-Intelligence-dashboard
   
   # Start all services
   docker-compose up -d
   ```

2. **Wait for Services** (30-60 seconds):
   ```bash
   # Check all services are running
   docker-compose ps
   ```

3. **Access the Platform**:
   - 📖 **API Documentation**: http://localhost:8000/docs
   - 📊 **Kibana Dashboard**: http://localhost:5601
   - 🔍 **API Health Check**: http://localhost:8000/health

### Test the System
```bash
# Test API endpoints
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/analytics/dashboard
curl http://localhost:8000/api/v1/enums
```

## 🔌 API Endpoints

### Core Endpoints
- `GET /health` - System health check
- `GET /api/v1/iocs` - Search IOCs with filters
- `GET /api/v1/threat-actors` - Search threat actors
- `GET /api/v1/alerts` - Security alerts
- `GET /api/v1/analytics/dashboard` - Dashboard data
- `GET /api/v1/enums` - Available enumeration values

### Example API Calls
```bash
# Search for malicious IPs
curl "http://localhost:8000/api/v1/iocs?type=ip&threat_level=high"

# Get dashboard statistics
curl "http://localhost:8000/api/v1/analytics/dashboard"

# Search APT groups
curl "http://localhost:8000/api/v1/threat-actors?actor_type=apt"
```

See [Frontend API Guide](docs/FRONTEND_API_GUIDE.md) for complete integration documentation.

## ⚙️ Configuration

- `config/api.yaml` - API server settings
- `config/kibana/kibana.yml` - Kibana configuration  
- `.env` - Environment variables
- `docker-compose.yml` - Service orchestration

## Threat Intelligence Sources

- MISP (Malware Information Sharing Platform)
- AlienVault OTX (Open Threat Exchange)
- VirusTotal API
- Shodan API
- Custom RSS/XML feeds
- STIX/TAXII feeds

## IOC Types Supported

- IP Addresses
- Domain Names
- File Hashes (MD5, SHA1, SHA256)
- URLs
- Email Addresses
- Registry Keys
- Network Signatures

## License

MIT License - see LICENSE file for details