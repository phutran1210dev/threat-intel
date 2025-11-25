#!/usr/bin/env python3
"""
🌱 Comprehensive Data Seeding Script for Threat Intelligence Dashboard
Seeds all types of threat intelligence data for comprehensive testing
"""

import asyncio
import sys
import os
import json
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

# Add project root to path
sys.path.append('/app')
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up Elasticsearch connection
from elasticsearch_dsl import connections
from elasticsearch import Elasticsearch
import requests

# Initialize Elasticsearch connection
es_url = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
es = Elasticsearch([es_url])
connections.create_connection(hosts=[es_url], alias='default')

# Import models
try:
    from src.models.ioc import IOCDocument, IOCType, ThreatLevel
    from src.models.threat_actor import ThreatActorDocument, ActorType
    from src.models.alert import AlertDocument, AlertSeverity, AlertStatus
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running this script from the project root directory")
    sys.exit(1)

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_section(title: str):
    """Print section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{title}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")

def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def print_info(message: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")

def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")

def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}❌ {message}{Colors.END}")

async def check_elasticsearch():
    """Check if Elasticsearch is available"""
    print_info("Checking Elasticsearch connection...")
    try:
        response = requests.get(f"{es_url}/_cluster/health", timeout=10)
        if response.status_code == 200:
            health = response.json()
            print_success(f"Elasticsearch is available - Status: {health['status']}")
            return True
        else:
            print_error(f"Elasticsearch returned status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Failed to connect to Elasticsearch: {e}")
        return False

async def initialize_indices():
    """Initialize all Elasticsearch indices"""
    print_info("Initializing Elasticsearch indices...")
    try:
        IOCDocument.init()
        print_success("IOC index initialized")
        
        ThreatActorDocument.init()
        print_success("Threat Actor index initialized")
        
        AlertDocument.init()
        print_success("Alert index initialized")
        
        return True
    except Exception as e:
        print_error(f"Failed to initialize indices: {e}")
        return False

async def create_comprehensive_iocs():
    """Create comprehensive IOC test data"""
    print_section("🔍 Creating IOC Test Data")
    
    # Extended IOC dataset for comprehensive testing
    sample_iocs = [
        # Malicious IPs
        {
            'value': '185.220.101.40', 'type': IOCType.IP, 'threat_level': ThreatLevel.CRITICAL,
            'source': 'misp', 'tags': ['tor-exit', 'botnet', 'c2'], 'confidence': 95,
            'description': 'Known Tor exit node used for C2 communication'
        },
        {
            'value': '192.168.1.100', 'type': IOCType.IP, 'threat_level': ThreatLevel.HIGH,
            'source': 'honeypot', 'tags': ['malware', 'botnet'], 'confidence': 85,
            'description': 'Banking trojan C2 server'
        },
        {
            'value': '203.0.113.45', 'type': IOCType.IP, 'threat_level': ThreatLevel.MEDIUM,
            'source': 'ids', 'tags': ['scanning', 'reconnaissance'], 'confidence': 70,
            'description': 'IP performing network reconnaissance'
        },
        {
            'value': '10.0.0.50', 'type': IOCType.IP, 'threat_level': ThreatLevel.CRITICAL,
            'source': 'apt-report', 'tags': ['apt28', 'persistence'], 'confidence': 98,
            'description': 'APT28 infrastructure hosting'
        },
        
        # Malicious Domains
        {
            'value': 'evil-phishing.com', 'type': IOCType.DOMAIN, 'threat_level': ThreatLevel.CRITICAL,
            'source': 'virustotal', 'tags': ['phishing', 'credential-theft', 'banking'], 'confidence': 95,
            'description': 'Phishing domain targeting major banks'
        },
        {
            'value': 'malware-dropper.net', 'type': IOCType.DOMAIN, 'threat_level': ThreatLevel.HIGH,
            'source': 'otx', 'tags': ['malware-distribution', 'exploit-kit'], 'confidence': 88,
            'description': 'Domain hosting exploit kit'
        },
        {
            'value': 'fake-update.org', 'type': IOCType.DOMAIN, 'threat_level': ThreatLevel.HIGH,
            'source': 'manual', 'tags': ['social-engineering', 'fake-software'], 'confidence': 82,
            'description': 'Fake software update site'
        },
        {
            'value': 'data-exfil.xyz', 'type': IOCType.DOMAIN, 'threat_level': ThreatLevel.MEDIUM,
            'source': 'sandbox', 'tags': ['data-exfiltration'], 'confidence': 75,
            'description': 'Domain used for data exfiltration'
        },
        
        # Malicious URLs
        {
            'value': 'http://malicious-site.net/exploit.php', 'type': IOCType.URL, 'threat_level': ThreatLevel.HIGH,
            'source': 'web-crawler', 'tags': ['exploit-kit', 'drive-by'], 'confidence': 80,
            'description': 'Drive-by download exploit page'
        },
        {
            'value': 'https://fake-bank.com/login.php', 'type': IOCType.URL, 'threat_level': ThreatLevel.CRITICAL,
            'source': 'phishtank', 'tags': ['phishing', 'banking'], 'confidence': 92,
            'description': 'Banking phishing page'
        },
        {
            'value': 'http://ransomware-payment.onion/pay', 'type': IOCType.URL, 'threat_level': ThreatLevel.HIGH,
            'source': 'dark-web', 'tags': ['ransomware', 'payment'], 'confidence': 85,
            'description': 'Ransomware payment portal'
        },
        
        # File Hashes - Various types
        {
            'value': '5d41402abc4b2a76b9719d911017c592', 'type': IOCType.FILE_HASH, 'threat_level': ThreatLevel.CRITICAL,
            'source': 'sandbox', 'tags': ['ransomware', 'wannacry'], 'confidence': 98,
            'description': 'WannaCry ransomware sample (MD5)'
        },
        {
            'value': '356a192b7913b04c54574d18c28d46e6395428ab', 'type': IOCType.FILE_HASH, 'threat_level': ThreatLevel.HIGH,
            'source': 'virustotal', 'tags': ['banking-trojan', 'emotet'], 'confidence': 90,
            'description': 'Emotet banking trojan (SHA1)'
        },
        {
            'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'type': IOCType.FILE_HASH, 'threat_level': ThreatLevel.MEDIUM,
            'source': 'yara', 'tags': ['backdoor', 'persistence'], 'confidence': 75,
            'description': 'Persistent backdoor sample (SHA256)'
        },
        
        # Email Addresses
        {
            'value': 'phisher@evil-domain.com', 'type': IOCType.EMAIL, 'threat_level': ThreatLevel.HIGH,
            'source': 'email-security', 'tags': ['phishing', 'bec'], 'confidence': 85,
            'description': 'Email address used in BEC campaigns'
        },
        {
            'value': 'malware-sender@spam.net', 'type': IOCType.EMAIL, 'threat_level': ThreatLevel.MEDIUM,
            'source': 'spam-trap', 'tags': ['malware-distribution'], 'confidence': 70,
            'description': 'Email distributing malware attachments'
        },
        
        # Registry Keys
        {
            'value': 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil', 'type': IOCType.REGISTRY_KEY, 'threat_level': ThreatLevel.HIGH,
            'source': 'endpoint-detection', 'tags': ['persistence', 'autoruns'], 'confidence': 88,
            'description': 'Registry key for malware persistence'
        },
        
        # User Agents
        {
            'value': 'EvilBot/1.0 (Windows NT 10.0; Win64; x64)', 'type': IOCType.USER_AGENT, 'threat_level': ThreatLevel.MEDIUM,
            'source': 'web-logs', 'tags': ['botnet', 'automation'], 'confidence': 65,
            'description': 'Suspicious user agent from botnet'
        }
    ]
    
    created_count = 0
    for ioc_data in sample_iocs:
        try:
            # Check if IOC already exists
            existing = IOCDocument.search().filter('term', value=ioc_data['value']).execute()
            if existing:
                print_warning(f"IOC {ioc_data['value']} already exists, skipping...")
                continue
                
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
                last_seen=datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 72)),
                first_seen=datetime.now(timezone.utc) - timedelta(days=random.randint(1, 30))
            )
            ioc.save()
            created_count += 1
            print_success(f"Created IOC: {ioc_data['value']} ({ioc_data['type'].value})")
        except Exception as e:
            print_error(f"Failed to create IOC {ioc_data['value']}: {e}")
    
    print_success(f"Successfully created {created_count} IOCs")
    return created_count

async def create_comprehensive_threat_actors():
    """Create comprehensive threat actor test data"""
    print_section("👤 Creating Threat Actor Test Data")
    
    threat_actors = [
        {
            'name': 'APT28 (Fancy Bear)',
            'actor_type': ActorType.APT,
            'aliases': ['Fancy Bear', 'Sofacy', 'Pawn Storm', 'Sednit'],
            'description': 'Russian military intelligence cyber espionage group',
            'country': 'Russia',
            'motivation': ['espionage', 'intelligence-gathering'],
            'sophistication': 'high',
            'targets': ['government', 'military', 'defense-contractors'],
            'ttps': ['spear-phishing', 'credential-harvesting', 'lateral-movement'],
            'tools': ['X-Agent', 'Sofacy', 'Komplex', 'GAMEFISH']
        },
        {
            'name': 'Lazarus Group',
            'actor_type': ActorType.APT,
            'aliases': ['Hidden Cobra', 'Guardians of Peace', 'APT38'],
            'description': 'North Korean state-sponsored threat group',
            'country': 'North Korea',
            'motivation': ['financial-gain', 'espionage', 'destruction'],
            'sophistication': 'high',
            'targets': ['financial', 'cryptocurrency', 'entertainment'],
            'ttps': ['supply-chain', 'destructive-attacks', 'swift-attacks'],
            'tools': ['Ratankba', 'Joanap', 'Brambul', 'PowerRatankba']
        },
        {
            'name': 'FIN7',
            'actor_type': ActorType.CYBERCRIMINAL,
            'aliases': ['Carbanak Group', 'Navigator Group'],
            'description': 'Financially motivated cybercriminal group',
            'country': 'Unknown',
            'motivation': ['financial-gain'],
            'sophistication': 'high',
            'targets': ['retail', 'restaurants', 'hospitality'],
            'ttps': ['spear-phishing', 'pos-malware', 'fileless-attacks'],
            'tools': ['Carbanak', 'BABYMETAL', 'HALFBAKED', 'DRIFTPIN']
        },
        {
            'name': 'Conti Ransomware Group',
            'actor_type': ActorType.CYBERCRIMINAL,
            'aliases': ['Conti Gang', 'Ryuk Successors'],
            'description': 'Ransomware-as-a-Service operation',
            'country': 'Russia',
            'motivation': ['financial-gain'],
            'sophistication': 'medium',
            'targets': ['healthcare', 'government', 'education'],
            'ttps': ['ransomware', 'double-extortion', 'affiliate-model'],
            'tools': ['Conti', 'Cobalt Strike', 'BazarLoader', 'Trickbot']
        },
        {
            'name': 'DarkHalo (UNC2452)',
            'actor_type': ActorType.APT,
            'aliases': ['SolarWinds Hackers', 'UNC2452', 'Nobelium'],
            'description': 'Sophisticated supply chain attack group',
            'country': 'Russia',
            'motivation': ['espionage', 'intelligence-gathering'],
            'sophistication': 'very-high',
            'targets': ['government', 'technology', 'cybersecurity'],
            'ttps': ['supply-chain', 'steganography', 'living-off-the-land'],
            'tools': ['SUNBURST', 'TEARDROP', 'Cobalt Strike', 'BEACON']
        }
    ]
    
    created_count = 0
    for actor_data in threat_actors:
        try:
            # Check if threat actor already exists
            existing = ThreatActorDocument.search().filter('term', name=actor_data['name']).execute()
            if existing:
                print_warning(f"Threat actor {actor_data['name']} already exists, skipping...")
                continue
                
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
            created_count += 1
            print_success(f"Created threat actor: {actor_data['name']}")
        except Exception as e:
            print_error(f"Failed to create threat actor {actor_data['name']}: {e}")
    
    print_success(f"Successfully created {created_count} threat actors")
    return created_count

async def create_comprehensive_alerts():
    """Create comprehensive alert test data"""
    print_section("🚨 Creating Alert Test Data")
    
    alerts = [
        {
            'title': 'Critical Phishing Campaign Detected',
            'description': 'Large-scale phishing campaign targeting financial institutions detected',
            'severity': AlertSeverity.CRITICAL,
            'status': AlertStatus.OPEN,
            'category': 'phishing',
            'ioc_matches': ['evil-phishing.com', 'fake-bank.com'],
            'threat_actor': 'FIN7'
        },
        {
            'title': 'APT28 Infrastructure Activity',
            'description': 'Known APT28 IP addresses showing increased activity',
            'severity': AlertSeverity.HIGH,
            'status': AlertStatus.INVESTIGATING,
            'category': 'apt-activity',
            'ioc_matches': ['185.220.101.40', '10.0.0.50'],
            'threat_actor': 'APT28 (Fancy Bear)'
        },
        {
            'title': 'Ransomware Sample Detected',
            'description': 'Known ransomware hash detected in network traffic',
            'severity': AlertSeverity.HIGH,
            'status': AlertStatus.OPEN,
            'category': 'malware',
            'ioc_matches': ['5d41402abc4b2a76b9719d911017c592'],
            'threat_actor': 'Conti Ransomware Group'
        },
        {
            'title': 'Suspicious Network Scanning',
            'description': 'Unusual network scanning patterns detected from external IP',
            'severity': AlertSeverity.MEDIUM,
            'status': AlertStatus.RESOLVED,
            'category': 'reconnaissance',
            'ioc_matches': ['203.0.113.45'],
            'threat_actor': None
        },
        {
            'title': 'Malware C2 Communication',
            'description': 'Endpoint communicating with known malware C2 server',
            'severity': AlertSeverity.HIGH,
            'status': AlertStatus.OPEN,
            'category': 'c2-communication',
            'ioc_matches': ['192.168.1.100', 'malware-dropper.net'],
            'threat_actor': 'Lazarus Group'
        },
        {
            'title': 'Data Exfiltration Attempt',
            'description': 'Large data transfer to suspicious external domain',
            'severity': AlertSeverity.CRITICAL,
            'status': AlertStatus.INVESTIGATING,
            'category': 'data-exfiltration',
            'ioc_matches': ['data-exfil.xyz'],
            'threat_actor': 'DarkHalo (UNC2452)'
        },
        {
            'title': 'Persistent Registry Modification',
            'description': 'Suspicious registry modification for persistence detected',
            'severity': AlertSeverity.MEDIUM,
            'status': AlertStatus.OPEN,
            'category': 'persistence',
            'ioc_matches': ['HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil'],
            'threat_actor': None
        },
        {
            'title': 'Suspicious Email Activity',
            'description': 'Phishing emails detected from known malicious sender',
            'severity': AlertSeverity.HIGH,
            'status': AlertStatus.RESOLVED,
            'category': 'email-threat',
            'ioc_matches': ['phisher@evil-domain.com'],
            'threat_actor': 'FIN7'
        }
    ]
    
    created_count = 0
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
                updated_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 24)),
                metadata={
                    'source_system': 'SIEM',
                    'confidence': random.randint(70, 95),
                    'false_positive_probability': random.randint(5, 25)
                }
            )
            alert.save()
            created_count += 1
            print_success(f"Created alert: {alert_data['title']}")
        except Exception as e:
            print_error(f"Failed to create alert {alert_data['title']}: {e}")
    
    print_success(f"Successfully created {created_count} alerts")
    return created_count

async def verify_data():
    """Verify all seeded data"""
    print_section("🔍 Verifying Seeded Data")
    
    try:
        # Count IOCs
        ioc_count = IOCDocument.search().count()
        print_info(f"Total IOCs in database: {ioc_count}")
        
        # Count by type
        for ioc_type in IOCType:
            type_count = IOCDocument.search().filter('term', type=ioc_type.value).count()
            print_info(f"  - {ioc_type.value}: {type_count}")
        
        # Count threat actors
        actor_count = ThreatActorDocument.search().count()
        print_info(f"Total Threat Actors: {actor_count}")
        
        # Count by type
        for actor_type in ActorType:
            type_count = ThreatActorDocument.search().filter('term', actor_type=actor_type.value).count()
            print_info(f"  - {actor_type.value}: {type_count}")
        
        # Count alerts
        alert_count = AlertDocument.search().count()
        print_info(f"Total Alerts: {alert_count}")
        
        # Count by severity
        for severity in AlertSeverity:
            severity_count = AlertDocument.search().filter('term', severity=severity.value).count()
            print_info(f"  - {severity.value}: {severity_count}")
        
        print_success("Data verification completed successfully!")
        return True
        
    except Exception as e:
        print_error(f"Data verification failed: {e}")
        return False

async def generate_sample_queries():
    """Generate sample queries for testing"""
    print_section("📝 Sample Queries for Testing")
    
    queries = [
        {
            'name': 'High Confidence IOCs',
            'query': 'GET /threat_iocs/_search?q=confidence:>90',
            'description': 'Find IOCs with confidence > 90%'
        },
        {
            'name': 'Critical Threat Level',
            'query': 'GET /threat_iocs/_search?q=threat_level:critical',
            'description': 'Find all critical threat level IOCs'
        },
        {
            'name': 'APT Threat Actors',
            'query': 'GET /threat_actors/_search?q=actor_type:apt',
            'description': 'Find all APT groups'
        },
        {
            'name': 'Open Critical Alerts',
            'query': 'GET /threat_alerts/_search?q=severity:critical AND status:open',
            'description': 'Find open critical alerts'
        },
        {
            'name': 'Russian Threat Actors',
            'query': 'GET /threat_actors/_search?q=country:Russia',
            'description': 'Find threat actors from Russia'
        },
        {
            'name': 'Phishing Related IOCs',
            'query': 'GET /threat_iocs/_search?q=tags:phishing',
            'description': 'Find all phishing-related IOCs'
        }
    ]
    
    print_info("Use these queries to test your data in Kibana or Elasticsearch:")
    for query in queries:
        print(f"\n{Colors.BOLD}{query['name']}:{Colors.END}")
        print(f"  Description: {query['description']}")
        print(f"  Query: {Colors.YELLOW}{query['query']}{Colors.END}")

async def main():
    """Main function to orchestrate data seeding"""
    print_section("🌱 Comprehensive Threat Intelligence Data Seeding")
    print_info("This script will seed comprehensive test data for the threat intelligence dashboard")
    
    # Check Elasticsearch connectivity
    if not await check_elasticsearch():
        print_error("Cannot proceed without Elasticsearch connectivity")
        return False
    
    # Initialize indices
    if not await initialize_indices():
        print_error("Failed to initialize indices")
        return False
    
    # Seed all data types
    total_created = 0
    
    try:
        # Create IOCs
        ioc_count = await create_comprehensive_iocs()
        total_created += ioc_count
        
        # Create Threat Actors
        actor_count = await create_comprehensive_threat_actors()
        total_created += actor_count
        
        # Create Alerts
        alert_count = await create_comprehensive_alerts()
        total_created += alert_count
        
        # Verify data
        await verify_data()
        
        # Generate sample queries
        await generate_sample_queries()
        
        print_section("🎉 Data Seeding Complete!")
        print_success(f"Successfully seeded {total_created} total records")
        print_info("Your threat intelligence dashboard is now ready for comprehensive testing!")
        print_info("Access Kibana at: http://localhost:5601")
        print_info("Access API docs at: http://localhost:8000/docs")
        
        return True
        
    except Exception as e:
        print_error(f"Data seeding failed: {e}")
        return False

if __name__ == "__main__":
    # Run the seeding process
    success = asyncio.run(main())
    sys.exit(0 if success else 1)