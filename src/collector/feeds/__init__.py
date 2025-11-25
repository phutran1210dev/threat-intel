"""
Threat intelligence feed implementations.
Supports multiple threat intelligence sources including MISP, OTX, VirusTotal, etc.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import aiohttp
import xml.etree.ElementTree as ET
import feedparser
import json

from src.models.ioc import IOCModel, IOCType, IOCSource, ThreatLevel, HashType

logger = logging.getLogger(__name__)


class BaseFeed(ABC):
    """Abstract base class for threat intelligence feeds."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the feed with configuration."""
        self.config = config
        self.name = self.__class__.__name__
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
            
    @abstractmethod
    async def collect(self) -> List[IOCModel]:
        """Collect IOCs from the feed."""
        pass
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check for the feed."""
        return {'status': 'healthy', 'feed': self.name}


class MISPFeed(BaseFeed):
    """MISP (Malware Information Sharing Platform) feed connector."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.url = config['url']
        self.api_key = config['api_key']
        self.verify_ssl = config.get('verify_ssl', True)
        self.tags = config.get('tags_to_fetch', [])
        
    async def collect(self) -> List[IOCModel]:
        """Collect IOCs from MISP."""
        iocs = []
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            # MISP API parameters
            params = {
                'returnFormat': 'json',
                'type': 'attributes',
                'category': ['Network activity', 'Payload delivery', 'Artifacts dropped'],
                'published': True,
                'to_ids': True,
                'last': '24h'  # Last 24 hours
            }
            
            if self.tags:
                params['tags'] = self.tags
                
            headers = {
                'Authorization': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            async with self.session.get(
                f"{self.url}/attributes/restSearch",
                params=params,
                headers=headers,
                ssl=self.verify_ssl
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for attribute in data.get('response', {}).get('Attribute', []):
                        ioc = await self._parse_misp_attribute(attribute)
                        if ioc:
                            iocs.append(ioc)
                            
                else:
                    logger.error(f"MISP API error: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error collecting from MISP: {e}")
            
        return iocs
        
    async def _parse_misp_attribute(self, attribute: Dict[str, Any]) -> Optional[IOCModel]:
        """Parse MISP attribute into IOC model."""
        try:
            # Map MISP types to our IOC types
            type_mapping = {
                'ip-src': IOCType.IP,
                'ip-dst': IOCType.IP,
                'domain': IOCType.DOMAIN,
                'hostname': IOCType.DOMAIN,
                'url': IOCType.URL,
                'email': IOCType.EMAIL,
                'email-src': IOCType.EMAIL,
                'email-dst': IOCType.EMAIL,
                'md5': IOCType.FILE_HASH,
                'sha1': IOCType.FILE_HASH,
                'sha256': IOCType.FILE_HASH,
                'sha512': IOCType.FILE_HASH,
                'regkey': IOCType.REGISTRY_KEY,
                'mutex': IOCType.MUTEX
            }
            
            misp_type = attribute.get('type', '')
            ioc_type = type_mapping.get(misp_type)
            
            if not ioc_type:
                return None
                
            # Determine hash type for file hashes
            hash_type = None
            if ioc_type == IOCType.FILE_HASH:
                if misp_type == 'md5':
                    hash_type = HashType.MD5
                elif misp_type == 'sha1':
                    hash_type = HashType.SHA1
                elif misp_type == 'sha256':
                    hash_type = HashType.SHA256
                elif misp_type == 'sha512':
                    hash_type = HashType.SHA512
                    
            # Map threat level
            threat_levels = {
                '1': ThreatLevel.HIGH,
                '2': ThreatLevel.MEDIUM,
                '3': ThreatLevel.LOW,
                '4': ThreatLevel.LOW
            }
            
            threat_level = threat_levels.get(
                attribute.get('Event', {}).get('threat_level_id', '2'),
                ThreatLevel.MEDIUM
            )
            
            # Create IOC source
            source = IOCSource(
                name="MISP",
                url=f"{self.url}/events/view/{attribute.get('event_id')}",
                confidence=80,  # MISP generally has high confidence
                first_seen=datetime.fromisoformat(attribute.get('timestamp', datetime.utcnow().isoformat())),
                last_seen=datetime.utcnow()
            )
            
            # Extract tags
            tags = [tag.get('name', '') for tag in attribute.get('Tag', [])]
            
            return IOCModel(
                value=attribute['value'],
                type=ioc_type,
                hash_type=hash_type,
                threat_level=threat_level,
                description=attribute.get('comment', ''),
                tags=tags,
                sources=[source],
                confidence=80
            )
            
        except Exception as e:
            logger.error(f"Error parsing MISP attribute: {e}")
            return None


class OTXFeed(BaseFeed):
    """AlienVault OTX (Open Threat Exchange) feed connector."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_key = config['api_key']
        self.pulse_types = config.get('pulse_types', ['malware'])
        self.base_url = "https://otx.alienvault.com/api/v1"
        
    async def collect(self) -> List[IOCModel]:
        """Collect IOCs from OTX."""
        iocs = []
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            headers = {
                'X-OTX-API-KEY': self.api_key,
                'Accept': 'application/json'
            }
            
            # Get recent pulses
            params = {
                'modified_since': (datetime.utcnow() - timedelta(days=1)).isoformat(),
                'limit': 100
            }
            
            async with self.session.get(
                f"{self.base_url}/pulses/subscribed",
                params=params,
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for pulse in data.get('results', []):
                        pulse_iocs = await self._parse_otx_pulse(pulse)
                        iocs.extend(pulse_iocs)
                        
                else:
                    logger.error(f"OTX API error: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error collecting from OTX: {e}")
            
        return iocs
        
    async def _parse_otx_pulse(self, pulse: Dict[str, Any]) -> List[IOCModel]:
        """Parse OTX pulse into IOC models."""
        iocs = []
        
        try:
            # Filter by pulse type
            pulse_tags = pulse.get('tags', [])
            if self.pulse_types and not any(pt in pulse_tags for pt in self.pulse_types):
                return iocs
                
            source = IOCSource(
                name="AlienVault OTX",
                url=f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                confidence=70,
                first_seen=datetime.fromisoformat(pulse.get('created')),
                last_seen=datetime.utcnow()
            )
            
            # Parse indicators
            for indicator in pulse.get('indicators', []):
                ioc = await self._parse_otx_indicator(indicator, pulse, source)
                if ioc:
                    iocs.append(ioc)
                    
        except Exception as e:
            logger.error(f"Error parsing OTX pulse: {e}")
            
        return iocs
        
    async def _parse_otx_indicator(self, indicator: Dict[str, Any], pulse: Dict[str, Any], source: IOCSource) -> Optional[IOCModel]:
        """Parse OTX indicator into IOC model."""
        try:
            # Map OTX types to our IOC types
            type_mapping = {
                'IPv4': IOCType.IP,
                'IPv6': IOCType.IP,
                'domain': IOCType.DOMAIN,
                'hostname': IOCType.DOMAIN,
                'URL': IOCType.URL,
                'email': IOCType.EMAIL,
                'FileHash-MD5': IOCType.FILE_HASH,
                'FileHash-SHA1': IOCType.FILE_HASH,
                'FileHash-SHA256': IOCType.FILE_HASH,
                'FileHash-SHA512': IOCType.FILE_HASH,
                'Mutex': IOCType.MUTEX
            }
            
            otx_type = indicator.get('type', '')
            ioc_type = type_mapping.get(otx_type)
            
            if not ioc_type:
                return None
                
            # Determine hash type
            hash_type = None
            if ioc_type == IOCType.FILE_HASH:
                if 'MD5' in otx_type:
                    hash_type = HashType.MD5
                elif 'SHA1' in otx_type:
                    hash_type = HashType.SHA1
                elif 'SHA256' in otx_type:
                    hash_type = HashType.SHA256
                elif 'SHA512' in otx_type:
                    hash_type = HashType.SHA512
                    
            # Determine threat level from pulse tags
            threat_level = ThreatLevel.MEDIUM
            pulse_tags = pulse.get('tags', [])
            
            if any(tag in ['apt', 'targeted', 'espionage'] for tag in pulse_tags):
                threat_level = ThreatLevel.HIGH
            elif any(tag in ['malware', 'trojan', 'ransomware'] for tag in pulse_tags):
                threat_level = ThreatLevel.HIGH
            elif any(tag in ['phishing', 'spam'] for tag in pulse_tags):
                threat_level = ThreatLevel.MEDIUM
                
            return IOCModel(
                value=indicator['indicator'],
                type=ioc_type,
                hash_type=hash_type,
                threat_level=threat_level,
                description=indicator.get('description', pulse.get('description', '')),
                tags=pulse_tags,
                sources=[source],
                confidence=70
            )
            
        except Exception as e:
            logger.error(f"Error parsing OTX indicator: {e}")
            return None


class VirusTotalFeed(BaseFeed):
    """VirusTotal feed connector."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_key = config['api_key']
        self.rate_limit = config.get('rate_limit', 4)  # requests per minute
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        
    async def collect(self) -> List[IOCModel]:
        """Collect IOCs from VirusTotal."""
        # Note: VirusTotal doesn't have a traditional feed API
        # This would typically be used for enriching existing IOCs
        # or collecting from their hunting/intelligence API (premium)
        
        logger.info("VirusTotal feed: Using for enrichment only")
        return []


class ShodanFeed(BaseFeed):
    """Shodan feed connector."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_key = config['api_key']
        self.base_url = "https://api.shodan.io"
        
    async def collect(self) -> List[IOCModel]:
        """Collect IOCs from Shodan."""
        iocs = []
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            # Search for potentially malicious hosts
            queries = [
                'product:"cobalt strike"',
                'title:"hacked by"',
                'http.title:"Index of"',
                'product:"metasploit"'
            ]
            
            for query in queries:
                query_iocs = await self._shodan_search(query)
                iocs.extend(query_iocs)
                
        except Exception as e:
            logger.error(f"Error collecting from Shodan: {e}")
            
        return iocs
        
    async def _shodan_search(self, query: str) -> List[IOCModel]:
        """Search Shodan and return IOCs."""
        iocs = []
        
        try:
            params = {
                'key': self.api_key,
                'query': query,
                'limit': 100
            }
            
            async with self.session.get(
                f"{self.base_url}/shodan/host/search",
                params=params
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for result in data.get('matches', []):
                        ioc = await self._parse_shodan_result(result, query)
                        if ioc:
                            iocs.append(ioc)
                            
        except Exception as e:
            logger.error(f"Error in Shodan search '{query}': {e}")
            
        return iocs
        
    async def _parse_shodan_result(self, result: Dict[str, Any], query: str) -> Optional[IOCModel]:
        """Parse Shodan search result into IOC model."""
        try:
            ip = result.get('ip_str')
            if not ip:
                return None
                
            source = IOCSource(
                name="Shodan",
                url=f"https://www.shodan.io/host/{ip}",
                confidence=60,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            
            # Extract tags from the query and result
            tags = [query.replace('"', '').replace(':', '_')]
            if 'tags' in result:
                tags.extend(result['tags'])
                
            return IOCModel(
                value=ip,
                type=IOCType.IP,
                threat_level=ThreatLevel.MEDIUM,
                description=f"Host found via Shodan search: {query}",
                tags=tags,
                sources=[source],
                confidence=60
            )
            
        except Exception as e:
            logger.error(f"Error parsing Shodan result: {e}")
            return None


class RSSFeed(BaseFeed):
    """Generic RSS/XML feed connector."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.feed_url = config['url']
        self.feed_name = config['name']
        
    async def collect(self) -> List[IOCModel]:
        """Collect IOCs from RSS feed."""
        iocs = []
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            async with self.session.get(self.feed_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Parse RSS feed
                    feed = feedparser.parse(content)
                    
                    for entry in feed.entries[:50]:  # Limit to recent entries
                        entry_iocs = await self._parse_rss_entry(entry)
                        iocs.extend(entry_iocs)
                        
        except Exception as e:
            logger.error(f"Error collecting from RSS feed {self.feed_name}: {e}")
            
        return iocs
        
    async def _parse_rss_entry(self, entry) -> List[IOCModel]:
        """Parse RSS entry for IOCs."""
        iocs = []
        
        try:
            # Extract IOCs from title and description using regex
            import re
            
            text = f"{entry.get('title', '')} {entry.get('description', '')} {entry.get('summary', '')}"
            
            # IP addresses
            ip_pattern = r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b'
            ips = re.findall(ip_pattern, text)
            
            for ip in ips:
                if self._is_valid_ip(ip):
                    ioc = await self._create_rss_ioc(ip, IOCType.IP, entry)
                    if ioc:
                        iocs.append(ioc)
                        
            # Domain names
            domain_pattern = r'\\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}\\b'
            domains = re.findall(domain_pattern, text)
            
            for domain in domains:
                if self._is_valid_domain(domain):
                    ioc = await self._create_rss_ioc(domain, IOCType.DOMAIN, entry)
                    if ioc:
                        iocs.append(ioc)
                        
            # File hashes
            hash_patterns = {
                HashType.MD5: r'\\b[a-fA-F0-9]{32}\\b',
                HashType.SHA1: r'\\b[a-fA-F0-9]{40}\\b',
                HashType.SHA256: r'\\b[a-fA-F0-9]{64}\\b'
            }
            
            for hash_type, pattern in hash_patterns.items():
                hashes = re.findall(pattern, text)
                for hash_value in hashes:
                    ioc = await self._create_rss_ioc(hash_value, IOCType.FILE_HASH, entry, hash_type)
                    if ioc:
                        iocs.append(ioc)
                        
        except Exception as e:
            logger.error(f"Error parsing RSS entry: {e}")
            
        return iocs
        
    async def _create_rss_ioc(self, value: str, ioc_type: IOCType, entry, hash_type: HashType = None) -> Optional[IOCModel]:
        """Create IOC from RSS entry data."""
        try:
            source = IOCSource(
                name=self.feed_name,
                url=entry.get('link', self.feed_url),
                confidence=50,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            
            return IOCModel(
                value=value,
                type=ioc_type,
                hash_type=hash_type,
                threat_level=ThreatLevel.MEDIUM,
                description=entry.get('title', ''),
                tags=[self.feed_name.lower()],
                sources=[source],
                confidence=50
            )
            
        except Exception as e:
            logger.error(f"Error creating RSS IOC: {e}")
            return None
            
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address."""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            # Skip private/local IPs
            ip_obj = ipaddress.ip_address(ip)
            return not ip_obj.is_private and not ip_obj.is_loopback
        except:
            return False
            
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name."""
        try:
            # Basic validation - skip common words and short domains
            if len(domain) < 4 or domain in ['com', 'org', 'net', 'www', 'http', 'https']:
                return False
            return '.' in domain and not domain.startswith('.')
        except:
            return False