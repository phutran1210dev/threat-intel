"""
IOC enrichment processor for threat intelligence dashboard.
Adds additional context and metadata to IOCs.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import aiohttp
import ipaddress
from datetime import datetime

from src.models.ioc import IOCModel, IOCType, GeoLocation, EnrichmentData

logger = logging.getLogger(__name__)


class IOCEnricher:
    """Enriches IOCs with additional context and metadata."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize enricher with configuration."""
        self.config = config
        self.enrichment_config = config.get('ioc_processing', {}).get('enrichment', {})
        self.max_concurrent = self.enrichment_config.get('max_concurrent', 10)
        self.timeout = self.enrichment_config.get('timeout', 30)
        
    async def enrich_batch(self, iocs: List[IOCModel]) -> List[IOCModel]:
        """Enrich a batch of IOCs concurrently."""
        if not self.enrichment_config.get('enabled', True):
            return iocs
            
        logger.info(f"Enriching {len(iocs)} IOCs")
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Enrich IOCs concurrently
        tasks = [self._enrich_single(ioc, semaphore) for ioc in iocs]
        enriched_iocs = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and return successful results
        result = []
        for ioc_result in enriched_iocs:
            if isinstance(ioc_result, IOCModel):
                result.append(ioc_result)
            elif isinstance(ioc_result, Exception):
                logger.error(f"Enrichment failed: {ioc_result}")
                
        return result
        
    async def _enrich_single(self, ioc: IOCModel, semaphore: asyncio.Semaphore) -> IOCModel:
        """Enrich a single IOC."""
        async with semaphore:
            try:
                # Initialize enrichment data if not present
                if not ioc.enrichment:
                    ioc.enrichment = EnrichmentData()
                    
                # Enrich based on IOC type
                if ioc.type == IOCType.IP:
                    await self._enrich_ip(ioc)
                elif ioc.type == IOCType.DOMAIN:
                    await self._enrich_domain(ioc)
                elif ioc.type == IOCType.URL:
                    await self._enrich_url(ioc)
                elif ioc.type == IOCType.EMAIL:
                    await self._enrich_email(ioc)
                elif ioc.type == IOCType.FILE_HASH:
                    await self._enrich_file_hash(ioc)
                    
                return ioc
                
            except Exception as e:
                logger.error(f"Error enriching IOC {ioc.value}: {e}")
                return ioc
                
    async def _enrich_ip(self, ioc: IOCModel):
        """Enrich IP address IOC."""
        try:
            ip = ipaddress.ip_address(ioc.value)
            
            # Skip private/local IPs
            if ip.is_private or ip.is_loopback or ip.is_multicast:
                return
                
            # Get geolocation
            geo_location = await self._get_ip_geolocation(ioc.value)
            if geo_location:
                ioc.enrichment.geo_location = geo_location
                
            # Get WHOIS data
            whois_data = await self._get_whois_data(ioc.value)
            if whois_data:
                ioc.enrichment.whois = whois_data
                
            # Get reputation data
            reputation = await self._get_ip_reputation(ioc.value)
            if reputation:
                ioc.enrichment.reputation = reputation
                
        except Exception as e:
            logger.error(f"Error enriching IP {ioc.value}: {e}")
            
    async def _enrich_domain(self, ioc: IOCModel):
        """Enrich domain IOC."""
        try:
            # Get DNS resolution
            dns_data = await self._get_dns_data(ioc.value)
            if dns_data:
                ioc.enrichment.dns = dns_data
                
                # If we got IP addresses, enrich with geolocation
                if 'A' in dns_data and dns_data['A']:
                    ip = dns_data['A'][0]  # Use first A record
                    geo_location = await self._get_ip_geolocation(ip)
                    if geo_location:
                        ioc.enrichment.geo_location = geo_location
                        
            # Get WHOIS data for domain
            whois_data = await self._get_whois_data(ioc.value)
            if whois_data:
                ioc.enrichment.whois = whois_data
                
            # Get reputation data
            reputation = await self._get_domain_reputation(ioc.value)
            if reputation:
                ioc.enrichment.reputation = reputation
                
        except Exception as e:
            logger.error(f"Error enriching domain {ioc.value}: {e}")
            
    async def _enrich_url(self, ioc: IOCModel):
        """Enrich URL IOC."""
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(ioc.value)
            domain = parsed.netloc
            
            if domain:
                # Enrich the domain part
                dns_data = await self._get_dns_data(domain)
                if dns_data:
                    ioc.enrichment.dns = dns_data
                    
                # Get reputation for URL
                reputation = await self._get_url_reputation(ioc.value)
                if reputation:
                    ioc.enrichment.reputation = reputation
                    
        except Exception as e:
            logger.error(f"Error enriching URL {ioc.value}: {e}")
            
    async def _enrich_email(self, ioc: IOCModel):
        """Enrich email IOC."""
        try:
            domain = ioc.value.split('@')[1] if '@' in ioc.value else None
            
            if domain:
                # Enrich the domain part
                dns_data = await self._get_dns_data(domain)
                if dns_data:
                    ioc.enrichment.dns = dns_data
                    
        except Exception as e:
            logger.error(f"Error enriching email {ioc.value}: {e}")
            
    async def _enrich_file_hash(self, ioc: IOCModel):
        """Enrich file hash IOC."""
        try:
            # Get reputation data for file hash
            reputation = await self._get_file_reputation(ioc.value)
            if reputation:
                ioc.enrichment.reputation = reputation
                
                # Extract malware family if available
                if 'malware_families' in reputation:
                    ioc.enrichment.malware_families = reputation['malware_families']
                    
        except Exception as e:
            logger.error(f"Error enriching file hash {ioc.value}: {e}")
            
    async def _get_ip_geolocation(self, ip: str) -> Optional[GeoLocation]:
        """Get geolocation data for IP address."""
        try:
            # Using ipapi.co for free geolocation
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(f"http://ip-api.com/json/{ip}") as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('status') == 'success':
                            return GeoLocation(
                                country=data.get('country'),
                                country_code=data.get('countryCode'),
                                city=data.get('city'),
                                latitude=data.get('lat'),
                                longitude=data.get('lon'),
                                asn=data.get('as'),
                                organization=data.get('org')
                            )
                            
        except Exception as e:
            logger.debug(f"Geolocation lookup failed for {ip}: {e}")
            
        return None
        
    async def _get_whois_data(self, target: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS data for IP or domain."""
        try:
            # Simple mock WHOIS data for demonstration
            # In production, you would use a proper WHOIS API
            return {
                'registrar': 'Unknown',
                'creation_date': None,
                'expiration_date': None,
                'last_updated': datetime.utcnow().isoformat(),
                'nameservers': []
            }
            
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {target}: {e}")
            
        return None
        
    async def _get_dns_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DNS resolution data for domain."""
        try:
            import socket
            
            dns_data = {}
            
            # Get A records (IPv4)
            try:
                a_records = socket.gethostbyname_ex(domain)[2]
                dns_data['A'] = a_records
            except:
                dns_data['A'] = []
                
            # Get AAAA records (IPv6) - simplified
            dns_data['AAAA'] = []
            
            # Mock MX and NS records for demonstration
            dns_data['MX'] = []
            dns_data['NS'] = []
            
            return dns_data
            
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
            
        return None
        
    async def _get_ip_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get reputation data for IP address."""
        try:
            # Mock reputation data
            # In production, integrate with reputation services
            return {
                'reputation_score': 50,
                'categories': [],
                'last_seen': datetime.utcnow().isoformat(),
                'threat_types': []
            }
            
        except Exception as e:
            logger.debug(f"IP reputation lookup failed for {ip}: {e}")
            
        return None
        
    async def _get_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get reputation data for domain."""
        try:
            # Mock reputation data
            return {
                'reputation_score': 50,
                'categories': [],
                'last_seen': datetime.utcnow().isoformat(),
                'threat_types': []
            }
            
        except Exception as e:
            logger.debug(f"Domain reputation lookup failed for {domain}: {e}")
            
        return None
        
    async def _get_url_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        """Get reputation data for URL."""
        try:
            # Mock reputation data
            return {
                'reputation_score': 50,
                'categories': [],
                'last_seen': datetime.utcnow().isoformat(),
                'threat_types': []
            }
            
        except Exception as e:
            logger.debug(f"URL reputation lookup failed for {url}: {e}")
            
        return None
        
    async def _get_file_reputation(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get reputation data for file hash."""
        try:
            # Mock reputation data
            return {
                'reputation_score': 30,  # Lower score indicates higher threat
                'malware_families': ['Generic.Trojan'],
                'detection_ratio': '5/67',
                'first_seen': datetime.utcnow().isoformat(),
                'last_analysis': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.debug(f"File reputation lookup failed for {file_hash}: {e}")
            
        return None