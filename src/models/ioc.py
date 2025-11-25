from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from elasticsearch_dsl import Document, Text, Keyword, Integer, Date, Float, Boolean, Nested


class IOCType(str, Enum):
    """Supported IOC types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"
    ASN = "asn"
    

class HashType(str, Enum):
    """Supported hash algorithms."""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SSDEEP = "ssdeep"
    

class ThreatLevel(str, Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    

class IOCStatus(str, Enum):
    """IOC processing status."""
    NEW = "new"
    PROCESSING = "processing"
    ENRICHED = "enriched"
    VALIDATED = "validated"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"


class IOCSource(BaseModel):
    """IOC source information."""
    name: str = Field(..., description="Source name")
    url: Optional[str] = Field(None, description="Source URL")
    confidence: int = Field(50, ge=0, le=100, description="Source confidence score")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    
    
class GeoLocation(BaseModel):
    """Geographic location information."""
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    organization: Optional[str] = None


class EnrichmentData(BaseModel):
    """IOC enrichment information."""
    whois: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    geo_location: Optional[GeoLocation] = None
    reputation: Optional[Dict[str, Any]] = None
    malware_families: Optional[List[str]] = None
    campaigns: Optional[List[str]] = None
    threat_actors: Optional[List[str]] = None
    

class IOCModel(BaseModel):
    """Pydantic model for IOC validation."""
    value: str = Field(..., description="IOC value")
    type: IOCType = Field(..., description="IOC type")
    hash_type: Optional[HashType] = Field(None, description="Hash algorithm for file hashes")
    threat_level: ThreatLevel = Field(ThreatLevel.MEDIUM, description="Threat severity")
    status: IOCStatus = Field(IOCStatus.NEW, description="Processing status")
    confidence: int = Field(50, ge=0, le=100, description="Confidence score")
    
    # Metadata
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    ttl_days: int = Field(30, gt=0, description="Time to live in days")
    
    # Source information
    sources: List[IOCSource] = Field(default_factory=list)
    
    # Enrichment data
    enrichment: Optional[EnrichmentData] = None
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    
    @validator('value')
    def validate_ioc_value(cls, v, values):
        """Validate IOC value based on type."""
        if 'type' not in values:
            return v
            
        ioc_type = values['type']
        
        if ioc_type == IOCType.IP:
            import ipaddress
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address: {v}")
                
        elif ioc_type == IOCType.DOMAIN:
            import re
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}$'
            if not re.match(domain_pattern, v):
                raise ValueError(f"Invalid domain: {v}")
                
        elif ioc_type == IOCType.EMAIL:
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, v):
                raise ValueError(f"Invalid email: {v}")
                
        elif ioc_type == IOCType.FILE_HASH:
            if 'hash_type' in values and values['hash_type']:
                hash_type = values['hash_type']
                expected_lengths = {
                    HashType.MD5: 32,
                    HashType.SHA1: 40,
                    HashType.SHA256: 64,
                    HashType.SHA512: 128
                }
                if hash_type in expected_lengths:
                    expected_len = expected_lengths[hash_type]
                    if len(v) != expected_len or not all(c in '0123456789abcdefABCDEF' for c in v):
                        raise ValueError(f"Invalid {hash_type.value} hash: {v}")
                        
        return v


class IOCDocument(Document):
    """Elasticsearch document for IOCs."""
    
    # Core IOC data
    value = Text(analyzer='keyword')
    type = Keyword()
    hash_type = Keyword()
    threat_level = Keyword()
    status = Keyword()
    confidence = Integer()
    
    # Metadata
    description = Text()
    tags = Keyword(multi=True)
    ttl_days = Integer()
    
    # Source information
    sources = Nested()
    
    # Enrichment data
    enrichment = Nested()
    
    # Timestamps
    created_at = Date()
    updated_at = Date()
    expires_at = Date()
    
    # Geographic data for visualization
    geo_point = Nested()
    
    class Index:
        name = 'threat_iocs'
        settings = {
            'number_of_shards': 2,
            'number_of_replicas': 1,
            'refresh_interval': '5s'
        }