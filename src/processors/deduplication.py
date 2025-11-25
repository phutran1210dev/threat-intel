"""
IOC deduplication processor for threat intelligence dashboard.
Prevents duplicate IOCs from being stored.
"""

import logging
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
import hashlib

from src.models.ioc import IOCModel, IOCSource
from src.database.elasticsearch_client import ElasticsearchClient

logger = logging.getLogger(__name__)


class IOCDeduplicator:
    """Handles deduplication of IOCs to prevent duplicates."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize deduplicator with configuration."""
        self.config = config
        self.dedup_config = config.get('ioc_processing', {}).get('deduplication', {})
        self.es_client = ElasticsearchClient(config['elasticsearch'])
        
        # Cache for recent IOCs to improve performance
        self.recent_iocs_cache: Dict[str, IOCModel] = {}
        self.cache_ttl = timedelta(minutes=30)
        self.last_cache_cleanup = datetime.utcnow()
        
    async def deduplicate(self, iocs: List[IOCModel]) -> List[IOCModel]:
        """Deduplicate a list of IOCs."""
        if not self.dedup_config.get('enabled', True):
            return iocs
            
        logger.info(f"Deduplicating {len(iocs)} IOCs")
        
        # Clean up cache periodically
        await self._cleanup_cache()
        
        unique_iocs = []
        processed_hashes: Set[str] = set()
        
        for ioc in iocs:
            try:
                # Generate hash for deduplication
                ioc_hash = self._generate_ioc_hash(ioc)
                
                # Check if we've already processed this IOC in this batch
                if ioc_hash in processed_hashes:
                    continue
                    
                # Check cache first
                cached_ioc = self.recent_iocs_cache.get(ioc_hash)
                if cached_ioc:
                    # Merge sources and update existing IOC
                    merged_ioc = await self._merge_iocs(cached_ioc, ioc)
                    self.recent_iocs_cache[ioc_hash] = merged_ioc
                    unique_iocs.append(merged_ioc)
                    processed_hashes.add(ioc_hash)
                    continue
                
                # Check database for existing IOC
                existing_ioc = await self._find_existing_ioc(ioc)
                if existing_ioc:
                    # Merge with existing IOC
                    merged_ioc = await self._merge_iocs(existing_ioc, ioc)
                    unique_iocs.append(merged_ioc)
                    
                    # Update cache
                    self.recent_iocs_cache[ioc_hash] = merged_ioc
                else:
                    # New unique IOC
                    unique_iocs.append(ioc)
                    self.recent_iocs_cache[ioc_hash] = ioc
                    
                processed_hashes.add(ioc_hash)
                
            except Exception as e:
                logger.error(f"Error deduplicating IOC {ioc.value}: {e}")
                # Include the IOC anyway to avoid data loss
                unique_iocs.append(ioc)
                
        logger.info(f"After deduplication: {len(unique_iocs)} unique IOCs")
        return unique_iocs
        
    def _generate_ioc_hash(self, ioc: IOCModel) -> str:
        """Generate hash for IOC deduplication."""
        hash_fields = self.dedup_config.get('hash_fields', ['value', 'type'])
        
        # Normalize value (lowercase, strip whitespace)
        normalized_value = ioc.value.lower().strip()
        
        # Create hash input
        hash_input = []
        for field in hash_fields:
            if field == 'value':
                hash_input.append(normalized_value)
            elif field == 'type':
                hash_input.append(ioc.type.value)
            elif hasattr(ioc, field):
                value = getattr(ioc, field)
                if value is not None:
                    hash_input.append(str(value))
                    
        # Generate SHA256 hash
        hash_string = '|'.join(hash_input)
        return hashlib.sha256(hash_string.encode()).hexdigest()
        
    async def _find_existing_ioc(self, ioc: IOCModel) -> IOCModel:
        """Find existing IOC in database."""
        try:
            # Search for IOC with same value and type
            query = {
                'value': ioc.value,
                'type': ioc.type.value
            }
            
            results = await self.es_client.search_iocs(query, size=1)
            
            if results['hits']:
                # Convert back to IOCModel
                existing_data = results['hits'][0]
                return IOCModel(**existing_data)
                
        except Exception as e:
            logger.error(f"Error searching for existing IOC: {e}")
            
        return None
        
    async def _merge_iocs(self, existing_ioc: IOCModel, new_ioc: IOCModel) -> IOCModel:
        """Merge two IOCs, combining their data."""
        try:
            # Start with existing IOC
            merged_ioc = existing_ioc.copy(deep=True)
            
            # Update last seen timestamp
            merged_ioc.updated_at = datetime.utcnow()
            
            # Merge sources
            existing_source_names = {source.name for source in merged_ioc.sources}
            
            for new_source in new_ioc.sources:
                if new_source.name not in existing_source_names:
                    merged_ioc.sources.append(new_source)
                else:
                    # Update existing source with latest data
                    for existing_source in merged_ioc.sources:
                        if existing_source.name == new_source.name:
                            existing_source.last_seen = new_source.last_seen
                            existing_source.confidence = max(
                                existing_source.confidence,
                                new_source.confidence
                            )
                            break
                            
            # Merge tags
            new_tags = set(new_ioc.tags) - set(merged_ioc.tags)
            merged_ioc.tags.extend(list(new_tags))
            
            # Update confidence to maximum
            merged_ioc.confidence = max(merged_ioc.confidence, new_ioc.confidence)
            
            # Update threat level to maximum
            threat_level_order = {
                'low': 1,
                'medium': 2, 
                'high': 3,
                'critical': 4
            }
            
            existing_level = threat_level_order.get(merged_ioc.threat_level.value, 2)
            new_level = threat_level_order.get(new_ioc.threat_level.value, 2)
            
            if new_level > existing_level:
                merged_ioc.threat_level = new_ioc.threat_level
                
            # Merge enrichment data if new IOC has it
            if new_ioc.enrichment:
                if not merged_ioc.enrichment:
                    merged_ioc.enrichment = new_ioc.enrichment
                else:
                    # Merge enrichment data
                    if new_ioc.enrichment.geo_location and not merged_ioc.enrichment.geo_location:
                        merged_ioc.enrichment.geo_location = new_ioc.enrichment.geo_location
                        
                    if new_ioc.enrichment.whois and not merged_ioc.enrichment.whois:
                        merged_ioc.enrichment.whois = new_ioc.enrichment.whois
                        
                    if new_ioc.enrichment.dns and not merged_ioc.enrichment.dns:
                        merged_ioc.enrichment.dns = new_ioc.enrichment.dns
                        
                    if new_ioc.enrichment.reputation and not merged_ioc.enrichment.reputation:
                        merged_ioc.enrichment.reputation = new_ioc.enrichment.reputation
                        
                    # Merge malware families
                    if new_ioc.enrichment.malware_families:
                        if not merged_ioc.enrichment.malware_families:
                            merged_ioc.enrichment.malware_families = new_ioc.enrichment.malware_families
                        else:
                            new_families = set(new_ioc.enrichment.malware_families) - set(merged_ioc.enrichment.malware_families)
                            merged_ioc.enrichment.malware_families.extend(list(new_families))
                            
                    # Merge campaigns
                    if new_ioc.enrichment.campaigns:
                        if not merged_ioc.enrichment.campaigns:
                            merged_ioc.enrichment.campaigns = new_ioc.enrichment.campaigns
                        else:
                            new_campaigns = set(new_ioc.enrichment.campaigns) - set(merged_ioc.enrichment.campaigns)
                            merged_ioc.enrichment.campaigns.extend(list(new_campaigns))
                            
                    # Merge threat actors
                    if new_ioc.enrichment.threat_actors:
                        if not merged_ioc.enrichment.threat_actors:
                            merged_ioc.enrichment.threat_actors = new_ioc.enrichment.threat_actors
                        else:
                            new_actors = set(new_ioc.enrichment.threat_actors) - set(merged_ioc.enrichment.threat_actors)
                            merged_ioc.enrichment.threat_actors.extend(list(new_actors))
                            
            # Update description if new one is more detailed
            if new_ioc.description and len(new_ioc.description) > len(merged_ioc.description or ''):
                merged_ioc.description = new_ioc.description
                
            return merged_ioc
            
        except Exception as e:
            logger.error(f"Error merging IOCs: {e}")
            # Return existing IOC if merge fails
            return existing_ioc
            
    async def _cleanup_cache(self):
        """Clean up expired entries from cache."""
        current_time = datetime.utcnow()
        
        # Only cleanup every 10 minutes
        if current_time - self.last_cache_cleanup < timedelta(minutes=10):
            return
            
        try:
            expired_keys = []
            
            for ioc_hash, ioc in self.recent_iocs_cache.items():
                # Remove IOCs older than cache TTL
                if current_time - ioc.updated_at > self.cache_ttl:
                    expired_keys.append(ioc_hash)
                    
            # Remove expired entries
            for key in expired_keys:
                del self.recent_iocs_cache[key]
                
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
                
            self.last_cache_cleanup = current_time
            
        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}")
            
    async def get_deduplication_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        return {
            'enabled': self.dedup_config.get('enabled', True),
            'cache_size': len(self.recent_iocs_cache),
            'cache_ttl_minutes': int(self.cache_ttl.total_seconds() / 60),
            'hash_fields': self.dedup_config.get('hash_fields', ['value', 'type']),
            'last_cache_cleanup': self.last_cache_cleanup.isoformat()
        }