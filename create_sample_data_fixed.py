#!/usr/bin/env python3
import asyncio
import sys
import os
sys.path.append('/app')

# Set up Elasticsearch connection first
from elasticsearch_dsl import connections
from elasticsearch import Elasticsearch

# Initialize Elasticsearch connection
es_url = os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200')
es = Elasticsearch([es_url])
connections.create_connection(hosts=[es_url], alias='default')

from src.models.ioc import IOCDocument, IOCType, ThreatLevel
from src.models.threat_actor import ThreatActorDocument, ActorType
from src.models.alert import AlertDocument, AlertSeverity, AlertStatus
from datetime import datetime, timezone

async def create_sample_data():
    print("🚀 Creating sample threat intelligence data...")
    
    # Initialize indices
    print("📋 Initializing Elasticsearch indices...")
    IOCDocument.init()
    ThreatActorDocument.init()
    AlertDocument.init()
    print("✅ Indices initialized")
    
    # Create sample IOCs
    sample_iocs = [
        {
            'value': '192.168.1.100', 'type': IOCType.IP, 'threat_level': ThreatLevel.HIGH,
            'source': 'misp', 'tags': ['malware', 'botnet'], 'confidence': 85,
            'description': 'Known C2 server for banking trojan'
        },
        {
            'value': 'evil-domain.com', 'type': IOCType.DOMAIN, 'threat_level': ThreatLevel.CRITICAL,
            'source': 'virustotal', 'tags': ['phishing', 'credential-theft'], 'confidence': 95,
            'description': 'Phishing domain targeting financial institutions'
        },
        {
            'value': '5d41402abc4b2a76b9719d911017c592', 'type': IOCType.FILE_HASH, 'threat_level': ThreatLevel.HIGH,
            'source': 'otx', 'tags': ['ransomware'], 'confidence': 90,
            'description': 'Ransomware payload hash'
        },
        {
            'value': 'http://malicious-site.net/exploit', 'type': IOCType.URL, 'threat_level': ThreatLevel.MEDIUM,
            'source': 'manual', 'tags': ['exploit-kit'], 'confidence': 75,
            'description': 'Exploit kit landing page'
        },
        {
            'value': '10.0.0.50', 'type': IOCType.IP, 'threat_level': ThreatLevel.CRITICAL,
            'source': 'misp', 'tags': ['apt', 'persistence'], 'confidence': 98,
            'description': 'APT group infrastructure IP'
        },
        {
            'value': 'badactor.org', 'type': IOCType.DOMAIN, 'threat_level': ThreatLevel.HIGH,
            'source': 'otx', 'tags': ['malware-distribution'], 'confidence': 88,
            'description': 'Malware distribution domain'
        },
        {
            'value': 'a1b2c3d4e5f6789012345678901234567890abcd', 'type': IOCType.FILE_HASH, 'threat_level': ThreatLevel.MEDIUM,
            'source': 'virustotal', 'tags': ['trojan'], 'confidence': 82,
            'description': 'Banking trojan sample'
        },
        {
            'value': '203.0.113.45', 'type': IOCType.IP, 'threat_level': ThreatLevel.LOW,
            'source': 'honeypot', 'tags': ['scanning'], 'confidence': 60,
            'description': 'IP observed in scanning activity'
        },
        {
            'value': 'suspicious-app.exe', 'type': IOCType.FILE_HASH, 'threat_level': ThreatLevel.MEDIUM,
            'source': 'av-vendor', 'tags': ['malware'], 'confidence': 78,
            'description': 'Suspicious executable detected by AV'
        },
        {
            'value': 'attack.example.com', 'type': IOCType.DOMAIN, 'threat_level': ThreatLevel.HIGH,
            'source': 'threat-feed', 'tags': ['command-control'], 'confidence': 92,
            'description': 'Command and control domain'
        }
    ]
    
    created_iocs = 0
    for ioc_data in sample_iocs:
        try:
            ioc = IOCDocument(
                value=ioc_data['value'],
                type=ioc_data['type'],
                threat_level=ioc_data['threat_level'],
                source=ioc_data['source'],
                tags=ioc_data['tags'],
                confidence=ioc_data['confidence'],
                description=ioc_data['description'],
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc)
            )
            ioc.save()
            print(f'✅ Created IOC: {ioc_data["value"]} ({ioc_data["type"].value})')
            created_iocs += 1
        except Exception as e:
            print(f'❌ Failed to create IOC {ioc_data["value"]}: {e}')
    
    # Create sample threat actors
    actors = [
        {
            'name': 'APT28', 'aliases': ['Fancy Bear', 'Sofacy'], 'actor_type': ActorType.APT,
            'description': 'Russian military intelligence cyber operations group',
            'ttps': ['spear-phishing', 'credential-theft', 'lateral-movement'],
            'targets': ['government', 'military', 'media']
        },
        {
            'name': 'Lazarus Group', 'aliases': ['Hidden Cobra', 'APT38'], 'actor_type': ActorType.APT,
            'description': 'North Korean state-sponsored threat group',
            'ttps': ['supply-chain-attacks', 'cryptocurrency-theft', 'destructive-attacks'],
            'targets': ['financial', 'cryptocurrency', 'infrastructure']
        },
        {
            'name': 'Carbanak', 'aliases': ['FIN7'], 'actor_type': ActorType.CYBERCRIMINAL,
            'description': 'Financial cybercriminal organization',
            'ttps': ['payment-card-theft', 'pos-malware', 'social-engineering'],
            'targets': ['retail', 'hospitality', 'financial']
        },
        {
            'name': 'Anonymous Collective', 'aliases': ['Anon'], 'actor_type': ActorType.HACKTIVIST,
            'description': 'Decentralized hacktivist collective',
            'ttps': ['ddos-attacks', 'website-defacement', 'data-leaks'],
            'targets': ['corporations', 'government', 'controversial-entities']
        },
        {
            'name': 'Conti Ransomware', 'aliases': ['Conti'], 'actor_type': ActorType.CYBERCRIMINAL,
            'description': 'Ransomware-as-a-Service operation',
            'ttps': ['ransomware', 'data-exfiltration', 'double-extortion'],
            'targets': ['healthcare', 'critical-infrastructure', 'manufacturing']
        }
    ]
    
    created_actors = 0
    for actor_data in actors:
        try:
            actor = ThreatActorDocument(
                name=actor_data['name'],
                aliases=actor_data['aliases'],
                actor_type=actor_data['actor_type'],
                description=actor_data['description'],
                ttps=actor_data['ttps'],
                targets=actor_data['targets'],
                first_seen=datetime.now(timezone.utc),
                last_active=datetime.now(timezone.utc)
            )
            actor.save()
            print(f'✅ Created Threat Actor: {actor_data["name"]}')
            created_actors += 1
        except Exception as e:
            print(f'❌ Failed to create threat actor {actor_data["name"]}: {e}')
    
    # Create sample alerts
    alerts = [
        {
            'title': 'High-risk IP detected in network traffic',
            'description': 'Multiple connections detected to known C2 server 192.168.1.100',
            'severity': AlertSeverity.HIGH, 'status': AlertStatus.OPEN,
            'source': 'network-monitor', 'related_iocs': ['192.168.1.100']
        },
        {
            'title': 'Phishing domain accessed by user',
            'description': 'User accessed known phishing domain evil-domain.com',
            'severity': AlertSeverity.CRITICAL, 'status': AlertStatus.INVESTIGATING,
            'source': 'web-proxy', 'related_iocs': ['evil-domain.com']
        },
        {
            'title': 'Malware hash detected in email attachment',
            'description': 'Email attachment contains known ransomware hash',
            'severity': AlertSeverity.HIGH, 'status': AlertStatus.OPEN,
            'source': 'email-scanner', 'related_iocs': ['5d41402abc4b2a76b9719d911017c592']
        },
        {
            'title': 'APT activity indicators observed',
            'description': 'Network traffic patterns consistent with APT28 TTPs detected',
            'severity': AlertSeverity.CRITICAL, 'status': AlertStatus.OPEN,
            'source': 'threat-hunter', 'related_iocs': ['10.0.0.50']
        },
        {
            'title': 'Suspicious domain registration',
            'description': 'Newly registered domain with suspicious characteristics',
            'severity': AlertSeverity.MEDIUM, 'status': AlertStatus.OPEN,
            'source': 'domain-monitor', 'related_iocs': ['badactor.org']
        },
        {
            'title': 'Banking trojan detected',
            'description': 'Known banking trojan hash found in system memory',
            'severity': AlertSeverity.HIGH, 'status': AlertStatus.INVESTIGATING,
            'source': 'edr-system', 'related_iocs': ['a1b2c3d4e5f6789012345678901234567890abcd']
        },
        {
            'title': 'Ransomware infection attempt blocked',
            'description': 'Ransomware payload blocked by endpoint protection',
            'severity': AlertSeverity.CRITICAL, 'status': AlertStatus.RESOLVED,
            'source': 'endpoint-protection', 'related_iocs': ['suspicious-app.exe']
        },
        {
            'title': 'C2 communication detected',
            'description': 'Outbound communication to known C2 domain observed',
            'severity': AlertSeverity.HIGH, 'status': AlertStatus.OPEN,
            'source': 'network-security', 'related_iocs': ['attack.example.com']
        }
    ]
    
    created_alerts = 0
    for alert_data in alerts:
        try:
            alert = AlertDocument(
                title=alert_data['title'],
                description=alert_data['description'],
                severity=alert_data['severity'],
                status=alert_data['status'],
                source=alert_data['source'],
                related_iocs=alert_data['related_iocs'],
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            alert.save()
            print(f'✅ Created Alert: {alert_data["title"]}')
            created_alerts += 1
        except Exception as e:
            print(f'❌ Failed to create alert {alert_data["title"]}: {e}')
    
    # Force refresh indices
    es.indices.refresh(index="threat_iocs")
    es.indices.refresh(index="threat_actors") 
    es.indices.refresh(index="threat_alerts")
    
    print('\n🎉 Sample data creation completed!')
    print(f'📊 Summary:')
    print(f'   - IOCs: {created_iocs}/{len(sample_iocs)} created')
    print(f'   - Threat Actors: {created_actors}/{len(actors)} created') 
    print(f'   - Alerts: {created_alerts}/{len(alerts)} created')
    print(f'   - Elasticsearch indices refreshed')

if __name__ == "__main__":
    asyncio.run(create_sample_data())