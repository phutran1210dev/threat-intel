# Threat Intelligence Dashboard - Architecture Guide

## System Architecture

The Threat Intelligence Dashboard is built with a microservices architecture designed for scalability, reliability, and real-time processing.

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Threat Feeds  │───▶│  Python Backend  │───▶│  Elasticsearch  │
│   (APIs/RSS)    │    │   (Collector)    │    │   (Storage)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │                          │
                              ▼                          ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Alert System   │◀───│  Analysis Engine │◀───│     Kibana      │
│  (Notifications)│    │  (IOC/Actors)    │    │ (Visualization) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                      ┌──────────────────┐
                      │   FastAPI REST   │
                      │      Server      │
                      └──────────────────┘
```

## Core Components

### 1. Data Collection Layer

**Threat Intelligence Collector** (`src/collector/`)
- Asynchronous data collection from multiple sources
- Rate limiting and error handling
- Data validation and normalization
- Deduplication and enrichment

**Supported Sources:**
- MISP (Malware Information Sharing Platform)
- AlienVault OTX (Open Threat Exchange)  
- VirusTotal API
- Shodan API
- Custom RSS/XML feeds
- STIX/TAXII feeds (extensible)

### 2. Data Storage Layer

**Elasticsearch** (Primary datastore)
- IOC storage with full-text search
- Threat actor profiles and relationships
- Alert storage and correlation
- Time-series data for trending
- Geographic data for mapping

**Index Structure:**
```
threat_iocs_*      - IOC data with metadata
threat_actors_*    - Threat actor profiles  
threat_alerts_*    - Security alerts
```

### 3. Processing Layer

**IOC Enrichment** (`src/processors/`)
- Geographic location resolution
- WHOIS data collection
- DNS resolution and history
- Reputation scoring
- Malware family attribution

**Threat Actor Profiling** (`src/models/threat_actor.py`)
- TTPs (Tactics, Techniques, Procedures) tracking
- Campaign attribution
- Infrastructure correlation
- Confidence scoring

### 4. Analysis Layer

**Alert Generation** (`src/alerting/`)
- Rule-based alert generation
- Risk scoring algorithms
- Correlation analysis
- False positive reduction

**Analytics Engine** (`src/api/`)
- Real-time statistics
- Trend analysis
- IOC correlation
- Threat landscape monitoring

### 5. API Layer

**FastAPI REST Server** (`src/api/`)
- RESTful API for data access
- Real-time search and filtering
- Pagination and sorting
- OpenAPI/Swagger documentation
- Rate limiting and authentication

**Key Endpoints:**
```
GET /api/v1/iocs              - Search IOCs
GET /api/v1/threat-actors     - Search threat actors
GET /api/v1/alerts           - Search alerts
GET /api/v1/analytics/dashboard - Dashboard data
```

### 6. Visualization Layer

**Kibana Dashboards**
- Real-time IOC monitoring
- Geographic threat mapping
- Alert management interface
- Trend visualization
- Custom dashboard creation

### 7. Alerting Layer

**Multi-Channel Notifications**
- Email alerts (SMTP)
- Slack integration
- Discord webhooks
- Custom webhook support
- Rate limiting and deduplication

## Data Models

### IOC (Indicator of Compromise)
```python
{
    "value": "192.168.1.100",
    "type": "ip",
    "threat_level": "high", 
    "confidence": 85,
    "sources": [...],
    "enrichment": {...},
    "tags": ["malware", "c2"],
    "created_at": "2025-01-01T00:00:00Z"
}
```

### Threat Actor
```python
{
    "name": "APT-Example",
    "actor_type": "apt",
    "sophistication": "advanced",
    "motivations": ["espionage"],
    "ttps": [...],
    "campaigns": [...],
    "infrastructure": [...],
    "threat_score": 85.5
}
```

### Alert
```python
{
    "title": "High Confidence IOC Detected",
    "severity": "high",
    "category": "ioc_match", 
    "risk_score": 78.5,
    "ioc_matches": [...],
    "threat_context": {...},
    "evidence": [...]
}
```

## Scalability Features

### Horizontal Scaling
- Stateless API servers
- Elasticsearch clustering
- Redis for session/cache management
- Docker containerization

### Performance Optimization
- Asynchronous processing
- Connection pooling
- Query optimization
- Caching strategies
- Background task processing

### High Availability
- Health checks and monitoring
- Graceful degradation
- Error handling and recovery
- Data backup strategies
- Rolling deployments

## Security Considerations

### Data Protection
- API key authentication
- Rate limiting
- Input validation
- SQL injection prevention
- XSS protection

### Network Security
- TLS/SSL encryption
- Network segmentation
- Firewall configuration
- Access control lists

### Operational Security
- Audit logging
- Error sanitization
- Secret management
- Regular security updates

## Monitoring and Observability

### Metrics Collection
- Application metrics (Prometheus compatible)
- Infrastructure metrics
- Business metrics (IOC counts, alert rates)
- Performance metrics

### Logging
- Structured logging (JSON format)
- Centralized log collection
- Log rotation and retention
- Security event logging

### Health Checks
- Application health endpoints
- Database connectivity checks
- External service monitoring
- Automated alerting

## Development Workflow

### Local Development
```bash
# Setup development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start dependencies
docker-compose up elasticsearch kibana redis

# Run services
python src/collector/main.py  # Data collector
python src/api/main.py        # API server
```

### Testing
```bash
# Unit tests
pytest tests/unit/

# Integration tests  
pytest tests/integration/

# API tests
pytest tests/api/
```

### Deployment
```bash
# Production deployment
docker-compose -f docker-compose.prod.yml up -d

# Health check
curl http://localhost:8000/health
```

## Configuration Management

All configuration is managed through `config/settings.yaml`:

- **Elasticsearch**: Connection, indices, templates
- **Threat Feeds**: API keys, endpoints, polling intervals
- **Alerting**: Notification channels, thresholds, rules
- **API**: CORS, rate limiting, authentication
- **Processing**: Enrichment settings, deduplication rules

## Extension Points

### Custom Threat Feeds
Implement the `BaseFeed` class to add new data sources:

```python
class CustomFeed(BaseFeed):
    async def collect(self) -> List[IOCModel]:
        # Custom collection logic
        pass
```

### Custom Alert Rules
Add new rules to the AlertManager:

```python
class CustomRule(AlertRule):
    async def evaluate(self, ioc: IOCModel) -> bool:
        # Custom rule logic
        pass
```

### Custom Enrichment
Extend the IOCEnricher for additional data sources:

```python
class CustomEnricher:
    async def enrich(self, ioc: IOCModel) -> IOCModel:
        # Custom enrichment logic
        pass
```

This architecture provides a robust, scalable foundation for threat intelligence operations while remaining flexible for customization and extension.