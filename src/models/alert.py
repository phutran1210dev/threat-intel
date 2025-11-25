"""
Alert data model for Elasticsearch
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from elasticsearch_dsl import Document, Text, Keyword, Date, Integer, Nested, Object, Float, Boolean
from enum import Enum


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Alert status"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertType(str, Enum):
    """Alert types"""
    IOC_MATCH = "ioc_match"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"
    ANOMALY = "anomaly"
    POLICY_VIOLATION = "policy_violation"
    NETWORK = "network"
    ENDPOINT = "endpoint"


class AlertDocument(Document):
    """Elasticsearch document for alerts"""
    
    # Basic Information
    title = Text(required=True)
    description = Text()
    alert_type = Keyword()
    severity = Keyword()
    status = Keyword(default='open')
    
    # Source Information
    source_system = Keyword()
    source_ip = Keyword()
    source_hostname = Keyword()
    source_user = Keyword()
    
    # Target Information  
    target_ip = Keyword()
    target_hostname = Keyword()
    target_user = Keyword()
    target_service = Keyword()
    target_port = Integer()
    
    # IOC Information
    ioc_type = Keyword()
    ioc_value = Keyword()
    ioc_description = Text()
    
    # Threat Intelligence
    threat_actor = Keyword()
    malware_family = Keyword()
    campaign = Keyword()
    
    # Detection
    rule_name = Keyword()
    rule_id = Keyword()
    signature_id = Integer()
    confidence_score = Integer()  # 0-100
    risk_score = Float()  # 0.0-10.0
    
    # Context
    event_count = Integer(default=1)
    first_seen = Date()
    last_seen = Date()
    duration = Integer()  # seconds
    
    # Network Details
    protocol = Keyword()
    src_bytes = Integer()
    dest_bytes = Integer()
    network_direction = Keyword()  # inbound, outbound, internal
    
    # File/Payload Information
    file_name = Keyword()
    file_hash = Keyword()
    file_size = Integer()
    file_type = Keyword()
    
    # MITRE ATT&CK
    mitre_tactics = Keyword(multi=True)
    mitre_techniques = Keyword(multi=True)
    kill_chain_phase = Keyword()
    
    # Evidence
    evidence = Nested(properties={
        'type': Keyword(),
        'value': Text(),
        'description': Text()
    })
    
    # Raw Event Data
    raw_data = Object(enabled=False)
    
    # Geolocation
    src_geo = Object(properties={
        'country': Keyword(),
        'region': Keyword(),
        'city': Keyword(),
        'latitude': Float(),
        'longitude': Float()
    })
    
    dest_geo = Object(properties={
        'country': Keyword(),
        'region': Keyword(), 
        'city': Keyword(),
        'latitude': Float(),
        'longitude': Float()
    })
    
    # Enrichment
    enrichment_sources = Keyword(multi=True)
    threat_feeds = Keyword(multi=True)
    
    # Response
    actions_taken = Keyword(multi=True)
    assigned_to = Keyword()
    notes = Text()
    
    # Tags and Labels
    tags = Keyword(multi=True)
    labels = Keyword(multi=True)
    
    # Tracking
    created_at = Date()
    updated_at = Date()
    acknowledged_at = Date()
    resolved_at = Date()
    created_by = Keyword()
    updated_by = Keyword()
    
    class Index:
        name = 'alerts'
        settings = {
            'number_of_shards': 1,
            'number_of_replicas': 0
        }


# Alias for backward compatibility  
AlertModel = AlertDocument

class Alert:
    """Pydantic model for API serialization"""
    
    def __init__(self, **data):
        self.title = data.get('title')
        self.description = data.get('description')
        self.alert_type = data.get('alert_type')
        self.severity = data.get('severity')
        self.status = data.get('status', 'open')
        
        # Source Information
        self.source_system = data.get('source_system')
        self.source_ip = data.get('source_ip')
        self.source_hostname = data.get('source_hostname')
        self.source_user = data.get('source_user')
        
        # Target Information
        self.target_ip = data.get('target_ip')
        self.target_hostname = data.get('target_hostname')
        self.target_user = data.get('target_user')
        self.target_service = data.get('target_service')
        self.target_port = data.get('target_port')
        
        # IOC Information
        self.ioc_type = data.get('ioc_type')
        self.ioc_value = data.get('ioc_value')
        self.ioc_description = data.get('ioc_description')
        
        # Threat Intelligence
        self.threat_actor = data.get('threat_actor')
        self.malware_family = data.get('malware_family')
        self.campaign = data.get('campaign')
        
        # Detection
        self.rule_name = data.get('rule_name')
        self.rule_id = data.get('rule_id')
        self.signature_id = data.get('signature_id')
        self.confidence_score = data.get('confidence_score')
        self.risk_score = data.get('risk_score')
        
        # Context
        self.event_count = data.get('event_count', 1)
        self.first_seen = data.get('first_seen')
        self.last_seen = data.get('last_seen')
        self.duration = data.get('duration')
        
        # Network Details
        self.protocol = data.get('protocol')
        self.src_bytes = data.get('src_bytes')
        self.dest_bytes = data.get('dest_bytes')
        self.network_direction = data.get('network_direction')
        
        # File Information
        self.file_name = data.get('file_name')
        self.file_hash = data.get('file_hash')
        self.file_size = data.get('file_size')
        self.file_type = data.get('file_type')
        
        # MITRE ATT&CK
        self.mitre_tactics = data.get('mitre_tactics', [])
        self.mitre_techniques = data.get('mitre_techniques', [])
        self.kill_chain_phase = data.get('kill_chain_phase')
        
        # Evidence
        self.evidence = data.get('evidence', [])
        self.raw_data = data.get('raw_data')
        
        # Geolocation
        self.src_geo = data.get('src_geo')
        self.dest_geo = data.get('dest_geo')
        
        # Enrichment
        self.enrichment_sources = data.get('enrichment_sources', [])
        self.threat_feeds = data.get('threat_feeds', [])
        
        # Response
        self.actions_taken = data.get('actions_taken', [])
        self.assigned_to = data.get('assigned_to')
        self.notes = data.get('notes')
        
        # Tags
        self.tags = data.get('tags', [])
        self.labels = data.get('labels', [])
        
        # Tracking
        self.created_at = data.get('created_at', datetime.utcnow())
        self.updated_at = data.get('updated_at', datetime.utcnow())
        self.acknowledged_at = data.get('acknowledged_at')
        self.resolved_at = data.get('resolved_at')
        self.created_by = data.get('created_by')
        self.updated_by = data.get('updated_by')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'title': self.title,
            'description': self.description,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'status': self.status,
            'source_system': self.source_system,
            'source_ip': self.source_ip,
            'source_hostname': self.source_hostname,
            'source_user': self.source_user,
            'target_ip': self.target_ip,
            'target_hostname': self.target_hostname,
            'target_user': self.target_user,
            'target_service': self.target_service,
            'target_port': self.target_port,
            'ioc_type': self.ioc_type,
            'ioc_value': self.ioc_value,
            'ioc_description': self.ioc_description,
            'threat_actor': self.threat_actor,
            'malware_family': self.malware_family,
            'campaign': self.campaign,
            'rule_name': self.rule_name,
            'rule_id': self.rule_id,
            'signature_id': self.signature_id,
            'confidence_score': self.confidence_score,
            'risk_score': self.risk_score,
            'event_count': self.event_count,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'duration': self.duration,
            'protocol': self.protocol,
            'src_bytes': self.src_bytes,
            'dest_bytes': self.dest_bytes,
            'network_direction': self.network_direction,
            'file_name': self.file_name,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques,
            'kill_chain_phase': self.kill_chain_phase,
            'evidence': self.evidence,
            'raw_data': self.raw_data,
            'src_geo': self.src_geo,
            'dest_geo': self.dest_geo,
            'enrichment_sources': self.enrichment_sources,
            'threat_feeds': self.threat_feeds,
            'actions_taken': self.actions_taken,
            'assigned_to': self.assigned_to,
            'notes': self.notes,
            'tags': self.tags,
            'labels': self.labels,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create instance from dictionary"""
        return cls(**data)