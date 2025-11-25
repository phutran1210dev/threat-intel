"""
Main threat intelligence collector service.
Orchestrates data collection from multiple threat intelligence sources.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import yaml
from pathlib import Path

from src.collector.feeds import (
    MISPFeed,
    OTXFeed,
    VirusTotalFeed,
    ShodanFeed,
    RSSFeed
)
from src.database.elasticsearch_client import ElasticsearchClient
from src.models.ioc import IOCModel, IOCDocument
from src.processors.enrichment import IOCEnricher
from src.processors.deduplication import IOCDeduplicator
from src.alerting.alert_manager import AlertManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatIntelligenceCollector:
    """Main threat intelligence collection orchestrator."""
    
    def __init__(self, config_path: str = "config/api.yaml"):
        """Initialize the collector with configuration."""
        self.config_path = Path(config_path)
        self.config = self._load_config()
        
        # Initialize components
        self.es_client = ElasticsearchClient(self.config['elasticsearch'])
        self.enricher = IOCEnricher(self.config)
        self.deduplicator = IOCDeduplicator(self.config)
        self.alert_manager = AlertManager(self.es_client, self.config.get('alerts', {}))
        
        # Initialize feeds
        self.feeds = self._initialize_feeds()
        
        # Runtime state
        self.running = False
        self.collection_stats = {
            'total_collected': 0,
            'total_processed': 0,
            'total_alerts': 0,
            'last_run': None,
            'errors': []
        }
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
            
    def _initialize_feeds(self) -> Dict[str, Any]:
        """Initialize threat intelligence feeds based on configuration."""
        feeds = {}
        
        feed_config = self.config.get('threat_feeds', {})
        
        # MISP Feed
        if feed_config.get('misp', {}).get('enabled', False):
            try:
                feeds['misp'] = MISPFeed(feed_config['misp'])
                logger.info("Initialized MISP feed")
            except Exception as e:
                logger.error(f"Failed to initialize MISP feed: {e}")
                
        # AlienVault OTX Feed
        if feed_config.get('otx', {}).get('enabled', False):
            try:
                feeds['otx'] = OTXFeed(feed_config['otx'])
                logger.info("Initialized OTX feed")
            except Exception as e:
                logger.error(f"Failed to initialize OTX feed: {e}")
                
        # VirusTotal Feed
        if feed_config.get('virustotal', {}).get('enabled', False):
            try:
                feeds['virustotal'] = VirusTotalFeed(feed_config['virustotal'])
                logger.info("Initialized VirusTotal feed")
            except Exception as e:
                logger.error(f"Failed to initialize VirusTotal feed: {e}")
                
        # Shodan Feed
        if feed_config.get('shodan', {}).get('enabled', False):
            try:
                feeds['shodan'] = ShodanFeed(feed_config['shodan'])
                logger.info("Initialized Shodan feed")
            except Exception as e:
                logger.error(f"Failed to initialize Shodan feed: {e}")
                
        # RSS Feeds
        rss_feeds = feed_config.get('rss_feeds', [])
        for rss_config in rss_feeds:
            if rss_config.get('enabled', False):
                try:
                    feed_name = f"rss_{rss_config['name'].lower()}"
                    feeds[feed_name] = RSSFeed(rss_config)
                    logger.info(f"Initialized RSS feed: {rss_config['name']}")
                except Exception as e:
                    logger.error(f"Failed to initialize RSS feed {rss_config['name']}: {e}")
                    
        return feeds
        
    async def collect_from_feed(self, feed_name: str, feed_instance: Any) -> List[IOCModel]:
        """Collect IOCs from a specific feed."""
        try:
            logger.info(f"Starting collection from {feed_name}")
            start_time = datetime.utcnow()
            
            # Collect IOCs from the feed
            iocs = await feed_instance.collect()
            
            logger.info(f"Collected {len(iocs)} IOCs from {feed_name} in "
                       f"{(datetime.utcnow() - start_time).total_seconds():.2f}s")
            
            self.collection_stats['total_collected'] += len(iocs)
            return iocs
            
        except Exception as e:
            error_msg = f"Error collecting from {feed_name}: {e}"
            logger.error(error_msg)
            self.collection_stats['errors'].append({
                'feed': feed_name,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            return []
            
    async def process_iocs(self, iocs: List[IOCModel]) -> List[IOCModel]:
        """Process IOCs through enrichment and deduplication."""
        if not iocs:
            return []
            
        try:
            logger.info(f"Processing {len(iocs)} IOCs")
            
            # Deduplicate IOCs
            unique_iocs = await self.deduplicator.deduplicate(iocs)
            logger.info(f"After deduplication: {len(unique_iocs)} unique IOCs")
            
            # Enrich IOCs
            if self.config.get('ioc_processing', {}).get('enrichment', {}).get('enabled', True):
                enriched_iocs = await self.enricher.enrich_batch(unique_iocs)
                logger.info(f"Enriched {len(enriched_iocs)} IOCs")
                return enriched_iocs
            else:
                return unique_iocs
                
        except Exception as e:
            logger.error(f"Error processing IOCs: {e}")
            return iocs
            
    async def store_iocs(self, iocs: List[IOCModel]) -> int:
        """Store IOCs in Elasticsearch."""
        if not iocs:
            return 0
            
        try:
            stored_count = 0
            
            for ioc in iocs:
                # Convert to Elasticsearch document
                doc = IOCDocument.from_model(ioc)
                
                # Store in Elasticsearch
                await self.es_client.index_document(doc, ioc.value)
                stored_count += 1
                
                # Check for alerts
                await self.check_for_alerts(ioc)
                
            logger.info(f"Stored {stored_count} IOCs in Elasticsearch")
            self.collection_stats['total_processed'] += stored_count
            
            return stored_count
            
        except Exception as e:
            logger.error(f"Error storing IOCs: {e}")
            return 0
            
    async def check_for_alerts(self, ioc: IOCModel):
        """Check if an IOC should trigger alerts."""
        try:
            # Generate alerts based on IOC characteristics
            alerts = await self.alert_manager.evaluate_ioc(ioc)
            
            for alert in alerts:
                await self.alert_manager.send_alert(alert)
                self.collection_stats['total_alerts'] += 1
                
        except Exception as e:
            logger.error(f"Error checking alerts for IOC {ioc.value}: {e}")
            
    async def run_collection_cycle(self):
        """Run a single collection cycle for all enabled feeds."""
        logger.info("Starting threat intelligence collection cycle")
        cycle_start = datetime.utcnow()
        
        all_iocs = []
        
        # Collect from all feeds concurrently
        collection_tasks = [
            self.collect_from_feed(feed_name, feed_instance)
            for feed_name, feed_instance in self.feeds.items()
        ]
        
        if collection_tasks:
            feed_results = await asyncio.gather(*collection_tasks, return_exceptions=True)
            
            # Combine results from all feeds
            for result in feed_results:
                if isinstance(result, list):
                    all_iocs.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Feed collection failed: {result}")
                    
        # Process and store IOCs
        if all_iocs:
            processed_iocs = await self.process_iocs(all_iocs)
            await self.store_iocs(processed_iocs)
            
        # Update statistics
        self.collection_stats['last_run'] = cycle_start.isoformat()
        cycle_duration = (datetime.utcnow() - cycle_start).total_seconds()
        
        logger.info(f"Collection cycle completed in {cycle_duration:.2f}s. "
                   f"Processed {len(all_iocs)} IOCs")
                   
    async def start_continuous_collection(self, interval_minutes: int = 60):
        """Start continuous threat intelligence collection."""
        logger.info(f"Starting continuous collection with {interval_minutes} minute intervals")
        self.running = True
        
        while self.running:
            try:
                await self.run_collection_cycle()
                
                # Wait for next collection cycle
                if self.running:
                    await asyncio.sleep(interval_minutes * 60)
                    
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, stopping collection")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Error in collection cycle: {e}")
                # Wait a bit before retrying
                if self.running:
                    await asyncio.sleep(300)  # 5 minutes
                    
        logger.info("Threat intelligence collection stopped")
        
    def stop_collection(self):
        """Stop the continuous collection."""
        logger.info("Stopping threat intelligence collection")
        self.running = False
        
    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        return self.collection_stats.copy()
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of all components."""
        health = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {}
        }
        
        # Check Elasticsearch
        try:
            es_health = await self.es_client.health_check()
            health['components']['elasticsearch'] = es_health
        except Exception as e:
            health['components']['elasticsearch'] = {'status': 'unhealthy', 'error': str(e)}
            health['status'] = 'degraded'
            
        # Check feeds
        for feed_name, feed_instance in self.feeds.items():
            try:
                if hasattr(feed_instance, 'health_check'):
                    feed_health = await feed_instance.health_check()
                else:
                    feed_health = {'status': 'unknown'}
                health['components'][feed_name] = feed_health
            except Exception as e:
                health['components'][feed_name] = {'status': 'unhealthy', 'error': str(e)}
                
        # Determine overall health
        unhealthy_components = [
            name for name, component in health['components'].items()
            if component.get('status') == 'unhealthy'
        ]
        
        if unhealthy_components:
            if len(unhealthy_components) > len(health['components']) / 2:
                health['status'] = 'unhealthy'
            else:
                health['status'] = 'degraded'
                
        return health


async def main():
    """Main entry point for the threat intelligence collector."""
    # Initialize collector
    collector = ThreatIntelligenceCollector()
    
    # Initialize Elasticsearch indices
    await collector.es_client.initialize_indices()
    
    try:
        # Start continuous collection
        await collector.start_continuous_collection(interval_minutes=60)
    except KeyboardInterrupt:
        logger.info("Shutting down threat intelligence collector")
    finally:
        collector.stop_collection()


if __name__ == "__main__":
    asyncio.run(main())