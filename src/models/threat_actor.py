"""
Threat Actor data model for Elasticsearch
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from elasticsearch_dsl import Document, Text, Keyword, Date, Integer, Nested, Object, Float, Boolean
from enum import Enum


class ThreatActorType(str, Enum):
    """Threat actor types"""
    APT = "apt"
    CYBERCRIMINAL = "cybercriminal"
    NATION_STATE = "nation_state"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    UNKNOWN = "unknown"


class ThreatActorDocument(Document):
    """Elasticsearch document for threat actors"""
    
    # Basic Information
    name = Keyword(required=True)
    aliases = Keyword(multi=True)
    description = Text()
    actor_type = Keyword()
    
    # Attribution
    country = Keyword()
    region = Keyword()
    sponsor = Keyword()
    
    # Activity
    first_seen = Date()
    last_seen = Date()
    active = Boolean(default=True)
    
    # Capabilities
    sophistication_level = Keyword()  # low, medium, high, expert
    primary_motivation = Keyword()  # financial, espionage, sabotage, ideology
    secondary_motivations = Keyword(multi=True)
    
    # Targets
    target_industries = Keyword(multi=True)
    target_countries = Keyword(multi=True)
    target_technologies = Keyword(multi=True)
    
    # TTPs (Tactics, Techniques, Procedures)
    attack_patterns = Nested(properties={
        'mitre_id': Keyword(),
        'name': Text(),
        'description': Text()
    })
    
    tools_used = Nested(properties={
        'name': Keyword(),
        'type': Keyword(),
        'description': Text()
    })
    
    malware_families = Keyword(multi=True)
    
    # Infrastructure
    infrastructure = Nested(properties={
        'type': Keyword(),  # domain, ip, url, etc.
        'value': Keyword(),
        'description': Text(),
        'active': Boolean()
    })
    
    # Associated Campaigns
    campaigns = Nested(properties={
        'name': Keyword(),
        'start_date': Date(),
        'end_date': Date(),
        'description': Text()
    })
    
    # Intelligence Sources
    sources = Nested(properties={
        'name': Keyword(),
        'url': Keyword(),
        'confidence': Integer(),
        'date': Date()
    })
    
    # Metadata
    confidence_score = Integer()  # 0-100
    threat_score = Float()  # 0.0-10.0
    tags = Keyword(multi=True)
    
    # Tracking
    created_at = Date()
    updated_at = Date()
    created_by = Keyword()
    updated_by = Keyword()
    
    class Index:
        name = 'threat-actors'
        settings = {
            'number_of_shards': 1,
            'number_of_replicas': 0
        }


# Alias for backward compatibility
ThreatActorModel = ThreatActorDocument
ActorType = ThreatActorType

class ThreatActor:
    """Pydantic model for API serialization"""
    
    def __init__(self, **data):
        self.name = data.get('name')
        self.aliases = data.get('aliases', [])
        self.description = data.get('description')
        self.actor_type = data.get('actor_type')
        self.country = data.get('country')
        self.region = data.get('region')
        self.sponsor = data.get('sponsor')
        self.first_seen = data.get('first_seen')
        self.last_seen = data.get('last_seen')
        self.active = data.get('active', True)
        self.sophistication_level = data.get('sophistication_level')
        self.primary_motivation = data.get('primary_motivation')
        self.secondary_motivations = data.get('secondary_motivations', [])
        self.target_industries = data.get('target_industries', [])
        self.target_countries = data.get('target_countries', [])
        self.target_technologies = data.get('target_technologies', [])
        self.attack_patterns = data.get('attack_patterns', [])
        self.tools_used = data.get('tools_used', [])
        self.malware_families = data.get('malware_families', [])
        self.infrastructure = data.get('infrastructure', [])
        self.campaigns = data.get('campaigns', [])
        self.sources = data.get('sources', [])
        self.confidence_score = data.get('confidence_score')
        self.threat_score = data.get('threat_score')
        self.tags = data.get('tags', [])
        self.created_at = data.get('created_at', datetime.utcnow())
        self.updated_at = data.get('updated_at', datetime.utcnow())
        self.created_by = data.get('created_by')
        self.updated_by = data.get('updated_by')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'aliases': self.aliases,
            'description': self.description,
            'actor_type': self.actor_type,
            'country': self.country,
            'region': self.region,
            'sponsor': self.sponsor,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'active': self.active,
            'sophistication_level': self.sophistication_level,
            'primary_motivation': self.primary_motivation,
            'secondary_motivations': self.secondary_motivations,
            'target_industries': self.target_industries,
            'target_countries': self.target_countries,
            'target_technologies': self.target_technologies,
            'attack_patterns': self.attack_patterns,
            'tools_used': self.tools_used,
            'malware_families': self.malware_families,
            'infrastructure': self.infrastructure,
            'campaigns': self.campaigns,
            'sources': self.sources,
            'confidence_score': self.confidence_score,
            'threat_score': self.threat_score,
            'tags': self.tags,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatActor':
        """Create instance from dictionary"""
        return cls(**data)