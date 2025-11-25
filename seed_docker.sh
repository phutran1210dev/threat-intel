#!/bin/bash

# 🌱 Docker-based Data Seeding Script
# Seeds data using the existing Docker container environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BOLD}${BLUE}============================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Check if Docker is running
check_docker() {
    if ! docker ps > /dev/null 2>&1; then
        print_error "Docker is not running or accessible"
        return 1
    fi
    print_success "Docker is running"
    return 0
}

# Check if threat intelligence containers are running
check_containers() {
    print_info "Checking threat intelligence containers..."
    
    # Check if elasticsearch container is running
    if ! docker ps | grep -q "threat-intel-elasticsearch"; then
        print_error "Elasticsearch container is not running"
        print_info "Please start with: docker-compose up -d elasticsearch"
        return 1
    fi
    print_success "Elasticsearch container is running"
    
    # Check if API container is running
    if ! docker ps | grep -q "threat-intel-api"; then
        print_error "API container is not running"
        print_info "Please start with: docker-compose up -d threat-api"
        return 1
    fi
    print_success "API container is running"
    
    return 0
}

# Wait for services to be ready
wait_for_services() {
    print_info "Waiting for services to be ready..."
    
    # Wait for Elasticsearch
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
            print_success "Elasticsearch is ready"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            print_error "Elasticsearch did not become ready in time"
            return 1
        fi
        
        print_info "Waiting for Elasticsearch... (attempt $attempt/$max_attempts)"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    return 0
}

# Create comprehensive seed data using Docker
seed_data_docker() {
    print_header "🌱 Creating Comprehensive Threat Intelligence Data"
    
    # Create temporary Python script for seeding
    cat > /tmp/docker_seed_data.py << 'EOF'
#!/usr/bin/env python3
import asyncio
import sys
import os
from datetime import datetime, timezone, timedelta
import random

# Set up Elasticsearch connection
from elasticsearch_dsl import connections, Document, Text, Keyword, Date, Integer, Float, Boolean
from elasticsearch import Elasticsearch

# Initialize Elasticsearch connection
es_url = 'http://elasticsearch:9200'
es = Elasticsearch([es_url])
connections.create_connection(hosts=[es_url], alias='default')

# Define IOC Document class
class IOCDocument(Document):
    value = Text()
    type = Keyword()
    threat_level = Keyword()
    source = Keyword()
    tags = Keyword()
    confidence = Integer()
    description = Text()
    created_at = Date()
    updated_at = Date()
    first_seen = Date()
    last_seen = Date()
    
    class Index:
        name = 'threat_iocs'

# Define Threat Actor Document class
class ThreatActorDocument(Document):
    name = Text()
    actor_type = Keyword()
    aliases = Keyword()
    description = Text()
    country = Keyword()
    motivation = Keyword()
    sophistication = Keyword()
    targets = Keyword()
    ttps = Keyword()
    tools = Keyword()
    first_seen = Date()
    last_seen = Date()
    created_at = Date()
    updated_at = Date()
    
    class Index:
        name = 'threat_actors'

# Define Alert Document class
class AlertDocument(Document):
    title = Text()
    description = Text()
    severity = Keyword()
    status = Keyword()
    category = Keyword()
    ioc_matches = Keyword()
    threat_actor = Text()
    created_at = Date()
    updated_at = Date()
    
    class Index:
        name = 'threat_alerts'

def create_sample_data():
    print("🚀 Creating comprehensive threat intelligence data...")
    
    # Initialize indices
    IOCDocument.init()
    ThreatActorDocument.init()
    AlertDocument.init()
    
    # Sample IOCs
    iocs = [
        {'value': '185.220.101.40', 'type': 'ip', 'threat_level': 'critical', 'source': 'misp', 'tags': ['tor-exit', 'botnet'], 'confidence': 95, 'description': 'Known Tor exit node used for C2'},
        {'value': '192.168.1.100', 'type': 'ip', 'threat_level': 'high', 'source': 'honeypot', 'tags': ['malware', 'botnet'], 'confidence': 85, 'description': 'Banking trojan C2 server'},
        {'value': 'evil-phishing.com', 'type': 'domain', 'threat_level': 'critical', 'source': 'virustotal', 'tags': ['phishing', 'banking'], 'confidence': 95, 'description': 'Phishing domain targeting banks'},
        {'value': 'malware-dropper.net', 'type': 'domain', 'threat_level': 'high', 'source': 'otx', 'tags': ['malware-distribution'], 'confidence': 88, 'description': 'Domain hosting exploit kit'},
        {'value': '5d41402abc4b2a76b9719d911017c592', 'type': 'file_hash', 'threat_level': 'critical', 'source': 'sandbox', 'tags': ['ransomware'], 'confidence': 98, 'description': 'WannaCry ransomware sample'},
        {'value': 'http://malicious-site.net/exploit.php', 'type': 'url', 'threat_level': 'high', 'source': 'web-crawler', 'tags': ['exploit-kit'], 'confidence': 80, 'description': 'Drive-by download page'},
        {'value': 'phisher@evil-domain.com', 'type': 'email', 'threat_level': 'high', 'source': 'email-security', 'tags': ['phishing'], 'confidence': 85, 'description': 'BEC campaign email'},
        {'value': '203.0.113.45', 'type': 'ip', 'threat_level': 'medium', 'source': 'ids', 'tags': ['scanning'], 'confidence': 70, 'description': 'IP performing reconnaissance'},
        {'value': 'fake-update.org', 'type': 'domain', 'threat_level': 'high', 'source': 'manual', 'tags': ['social-engineering'], 'confidence': 82, 'description': 'Fake software update site'},
        {'value': '356a192b7913b04c54574d18c28d46e6395428ab', 'type': 'file_hash', 'threat_level': 'high', 'source': 'virustotal', 'tags': ['banking-trojan'], 'confidence': 90, 'description': 'Emotet banking trojan'},
        {'value': 'data-exfil.xyz', 'type': 'domain', 'threat_level': 'medium', 'source': 'sandbox', 'tags': ['data-exfiltration'], 'confidence': 75, 'description': 'Data exfiltration domain'},
        {'value': '10.0.0.50', 'type': 'ip', 'threat_level': 'critical', 'source': 'apt-report', 'tags': ['apt28'], 'confidence': 98, 'description': 'APT28 infrastructure'},
        {'value': 'https://fake-bank.com/login.php', 'type': 'url', 'threat_level': 'critical', 'source': 'phishtank', 'tags': ['phishing'], 'confidence': 92, 'description': 'Banking phishing page'},
        {'value': 'badactor.org', 'type': 'domain', 'threat_level': 'high', 'source': 'otx', 'tags': ['malware-distribution'], 'confidence': 88, 'description': 'Malware distribution domain'},
        {'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'type': 'file_hash', 'threat_level': 'medium', 'source': 'yara', 'tags': ['backdoor'], 'confidence': 75, 'description': 'Persistent backdoor sample'},
        {'value': 'malware-sender@spam.net', 'type': 'email', 'threat_level': 'medium', 'source': 'spam-trap', 'tags': ['malware-distribution'], 'confidence': 70, 'description': 'Malware distribution email'}
    ]
    
    created_iocs = 0
    for ioc_data in iocs:
        try:
            ioc = IOCDocument(
                value=ioc_data['value'],
                type=ioc_data['type'],
                threat_level=ioc_data['threat_level'],
                source=ioc_data['source'],
                tags=ioc_data['tags'],
                confidence=ioc_data['confidence'],
                description=ioc_data['description'],
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                first_seen=datetime.now(timezone.utc) - timedelta(days=random.randint(1, 30)),
                last_seen=datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 72))
            )
            ioc.save()
            created_iocs += 1
            print(f"✅ Created IOC: {ioc_data['value']} ({ioc_data['type']})")
        except Exception as e:
            print(f"❌ Failed to create IOC {ioc_data['value']}: {e}")
    
    # Sample Threat Actors
    actors = [
        {
            'name': 'APT28 (Fancy Bear)',
            'actor_type': 'apt',
            'aliases': ['Fancy Bear', 'Sofacy', 'Pawn Storm'],
            'description': 'Russian military intelligence cyber espionage group',
            'country': 'Russia',
            'motivation': ['espionage', 'intelligence-gathering'],
            'sophistication': 'high',
            'targets': ['government', 'military'],
            'ttps': ['spear-phishing', 'credential-harvesting'],
            'tools': ['X-Agent', 'Sofacy', 'Komplex']
        },
        {
            'name': 'Lazarus Group',
            'actor_type': 'apt',
            'aliases': ['Hidden Cobra', 'Guardians of Peace'],
            'description': 'North Korean state-sponsored threat group',
            'country': 'North Korea',
            'motivation': ['financial-gain', 'espionage'],
            'sophistication': 'high',
            'targets': ['financial', 'cryptocurrency'],
            'ttps': ['supply-chain', 'destructive-attacks'],
            'tools': ['Ratankba', 'Joanap', 'Brambul']
        },
        {
            'name': 'FIN7',
            'actor_type': 'cybercriminal',
            'aliases': ['Carbanak Group', 'Navigator Group'],
            'description': 'Financially motivated cybercriminal group',
            'country': 'Unknown',
            'motivation': ['financial-gain'],
            'sophistication': 'high',
            'targets': ['retail', 'restaurants', 'hospitality'],
            'ttps': ['spear-phishing', 'pos-malware'],
            'tools': ['Carbanak', 'BABYMETAL', 'HALFBAKED']
        },
        {
            'name': 'Conti Ransomware Group',
            'actor_type': 'cybercriminal',
            'aliases': ['Conti Gang', 'Ryuk Successors'],
            'description': 'Ransomware-as-a-Service operation',
            'country': 'Russia',
            'motivation': ['financial-gain'],
            'sophistication': 'medium',
            'targets': ['healthcare', 'government', 'education'],
            'ttps': ['ransomware', 'double-extortion'],
            'tools': ['Conti', 'Cobalt Strike', 'BazarLoader']
        },
        {
            'name': 'DarkHalo (UNC2452)',
            'actor_type': 'apt',
            'aliases': ['SolarWinds Hackers', 'UNC2452', 'Nobelium'],
            'description': 'Sophisticated supply chain attack group',
            'country': 'Russia',
            'motivation': ['espionage', 'intelligence-gathering'],
            'sophistication': 'very-high',
            'targets': ['government', 'technology', 'cybersecurity'],
            'ttps': ['supply-chain', 'steganography'],
            'tools': ['SUNBURST', 'TEARDROP', 'Cobalt Strike']
        }
    ]
    
    created_actors = 0
    for actor_data in actors:
        try:
            actor = ThreatActorDocument(
                name=actor_data['name'],
                actor_type=actor_data['actor_type'],
                aliases=actor_data['aliases'],
                description=actor_data['description'],
                country=actor_data['country'],
                motivation=actor_data['motivation'],
                sophistication=actor_data['sophistication'],
                targets=actor_data['targets'],
                ttps=actor_data['ttps'],
                tools=actor_data['tools'],
                first_seen=datetime.now(timezone.utc) - timedelta(days=random.randint(100, 1000)),
                last_seen=datetime.now(timezone.utc) - timedelta(days=random.randint(1, 30)),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            actor.save()
            created_actors += 1
            print(f"✅ Created threat actor: {actor_data['name']}")
        except Exception as e:
            print(f"❌ Failed to create actor {actor_data['name']}: {e}")
    
    # Sample Alerts
    alerts = [
        {'title': 'Critical Phishing Campaign Detected', 'description': 'Large-scale phishing campaign targeting financial institutions', 'severity': 'critical', 'status': 'open', 'category': 'phishing', 'ioc_matches': ['evil-phishing.com'], 'threat_actor': 'FIN7'},
        {'title': 'APT28 Infrastructure Activity', 'description': 'Known APT28 IP addresses showing increased activity', 'severity': 'high', 'status': 'investigating', 'category': 'apt-activity', 'ioc_matches': ['185.220.101.40'], 'threat_actor': 'APT28 (Fancy Bear)'},
        {'title': 'Ransomware Sample Detected', 'description': 'Known ransomware hash detected in network traffic', 'severity': 'high', 'status': 'open', 'category': 'malware', 'ioc_matches': ['5d41402abc4b2a76b9719d911017c592'], 'threat_actor': 'Conti Ransomware Group'},
        {'title': 'Suspicious Network Scanning', 'description': 'Unusual network scanning patterns detected', 'severity': 'medium', 'status': 'resolved', 'category': 'reconnaissance', 'ioc_matches': ['203.0.113.45'], 'threat_actor': None},
        {'title': 'Malware C2 Communication', 'description': 'Endpoint communicating with known malware C2 server', 'severity': 'high', 'status': 'open', 'category': 'c2-communication', 'ioc_matches': ['192.168.1.100'], 'threat_actor': 'Lazarus Group'},
        {'title': 'Data Exfiltration Attempt', 'description': 'Large data transfer to suspicious external domain', 'severity': 'critical', 'status': 'investigating', 'category': 'data-exfiltration', 'ioc_matches': ['data-exfil.xyz'], 'threat_actor': 'DarkHalo (UNC2452)'},
        {'title': 'Suspicious Email Activity', 'description': 'Phishing emails detected from known malicious sender', 'severity': 'high', 'status': 'resolved', 'category': 'email-threat', 'ioc_matches': ['phisher@evil-domain.com'], 'threat_actor': 'FIN7'},
        {'title': 'Banking Trojan Detection', 'description': 'Banking trojan sample detected on endpoint', 'severity': 'high', 'status': 'open', 'category': 'malware', 'ioc_matches': ['356a192b7913b04c54574d18c28d46e6395428ab'], 'threat_actor': None}
    ]
    
    created_alerts = 0
    for alert_data in alerts:
        try:
            alert = AlertDocument(
                title=alert_data['title'],
                description=alert_data['description'],
                severity=alert_data['severity'],
                status=alert_data['status'],
                category=alert_data['category'],
                ioc_matches=alert_data['ioc_matches'],
                threat_actor=alert_data['threat_actor'],
                created_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 168)),
                updated_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 24))
            )
            alert.save()
            created_alerts += 1
            print(f"✅ Created alert: {alert_data['title']}")
        except Exception as e:
            print(f"❌ Failed to create alert {alert_data['title']}: {e}")
    
    print(f"\n🎉 Data seeding completed successfully!")
    print(f"📊 Summary:")
    print(f"   • IOCs created: {created_iocs}")
    print(f"   • Threat Actors created: {created_actors}")
    print(f"   • Alerts created: {created_alerts}")
    print(f"   • Total records: {created_iocs + created_actors + created_alerts}")

if __name__ == "__main__":
    create_sample_data()
EOF

    # Copy script to API container and execute
    print_info "Copying seeding script to API container..."
    docker cp /tmp/docker_seed_data.py threat-intel-api:/tmp/seed_data.py
    
    print_info "Executing data seeding in API container..."
    docker exec threat-intel-api python /tmp/seed_data.py
    
    # Clean up
    rm -f /tmp/docker_seed_data.py
    docker exec threat-intel-api rm -f /tmp/seed_data.py
    
    print_success "Data seeding completed using Docker container"
}

# Verify seeded data
verify_data() {
    print_header "🔍 Verifying Seeded Data"
    
    # Check IOC count
    local ioc_count=$(curl -s "http://localhost:9200/threat_iocs/_count" | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
    print_info "IOCs in database: $ioc_count"
    
    # Check Threat Actor count
    local actor_count=$(curl -s "http://localhost:9200/threat_actors/_count" | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
    print_info "Threat Actors in database: $actor_count"
    
    # Check Alert count
    local alert_count=$(curl -s "http://localhost:9200/threat_alerts/_count" | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
    print_info "Alerts in database: $alert_count"
    
    local total=$((ioc_count + actor_count + alert_count))
    
    if [ $total -gt 0 ]; then
        print_success "Total records in database: $total"
        return 0
    else
        print_error "No data found in database!"
        return 1
    fi
}

# Show sample queries
show_sample_queries() {
    print_header "📝 Sample Elasticsearch Queries"
    
    echo "Use these queries to test your data:"
    echo ""
    echo "1. Count all IOCs:"
    echo "   curl http://localhost:9200/threat_iocs/_count"
    echo ""
    echo "2. Search critical IOCs:"
    echo "   curl 'http://localhost:9200/threat_iocs/_search?q=threat_level:critical'"
    echo ""
    echo "3. Find APT groups:"
    echo "   curl 'http://localhost:9200/threat_actors/_search?q=actor_type:apt'"
    echo ""
    echo "4. Open alerts:"
    echo "   curl 'http://localhost:9200/threat_alerts/_search?q=status:open'"
    echo ""
    echo "5. Phishing IOCs:"
    echo "   curl 'http://localhost:9200/threat_iocs/_search?q=tags:phishing'"
}

# Show access information
show_access_info() {
    print_header "🚀 Dashboard Access Information"
    
    print_success "Your threat intelligence dashboard is ready!"
    echo ""
    echo "📊 Access Points:"
    echo "   • Kibana Dashboard: http://localhost:5601"
    echo "   • API Documentation: http://localhost:8000/docs"
    echo "   • Elasticsearch: http://localhost:9200"
    echo ""
    echo "🔍 Quick Tests:"
    echo "   • curl http://localhost:8000/api/v1/iocs"
    echo "   • curl http://localhost:8000/api/v1/threat-actors"
    echo "   • curl http://localhost:8000/api/v1/alerts"
}

# Main execution
main() {
    print_header "🌱 Docker-based Threat Intelligence Data Seeding"
    
    # Step 1: Check Docker
    if ! check_docker; then
        exit 1
    fi
    
    # Step 2: Check containers
    if ! check_containers; then
        print_info "To start all services, run:"
        print_info "  docker-compose up -d"
        exit 1
    fi
    
    # Step 3: Wait for services
    if ! wait_for_services; then
        exit 1
    fi
    
    # Step 4: Seed data
    if ! seed_data_docker; then
        print_error "Data seeding failed"
        exit 1
    fi
    
    # Step 5: Verify data
    if ! verify_data; then
        print_warning "Data verification had issues"
    fi
    
    # Step 6: Show queries and access info
    show_sample_queries
    show_access_info
    
    print_header "🎉 Seeding Complete!"
    print_success "Your threat intelligence dashboard is ready for testing!"
}

# Run main function
main "$@"