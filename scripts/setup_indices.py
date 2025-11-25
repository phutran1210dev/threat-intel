#!/usr/bin/env python3
"""
Setup script for threat intelligence dashboard.
Initializes Elasticsearch indices, Kibana dashboards, and sample data.
"""

import asyncio
import json
import logging
from pathlib import Path
import aiohttp
import yaml
from datetime import datetime, timedelta

from src.database.elasticsearch_client import ElasticsearchClient
from src.models.ioc import IOCModel, IOCType, IOCSource, ThreatLevel, HashType
from src.models.threat_actor import ThreatActorModel, ActorType, Sophistication, Motivation
from src.models.alert import AlertModel, AlertRule, AlertSeverity, AlertCategory

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SetupManager:
    """Manages setup and initialization of the threat intelligence dashboard."""
    
    def __init__(self):
        """Initialize setup manager."""
        # Load configuration
        config_path = Path("config/settings.yaml")
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        # Initialize clients
        self.es_client = ElasticsearchClient(self.config['elasticsearch'])
        
    async def setup_elasticsearch(self):
        """Setup Elasticsearch indices and templates."""
        logger.info("Setting up Elasticsearch indices...")
        
        try:
            # Initialize indices
            await self.es_client.initialize_indices()
            
            # Wait for cluster to be ready
            await asyncio.sleep(5)
            
            # Verify indices were created
            indices = ['threat_iocs', 'threat_actors', 'threat_alerts']
            for index in indices:
                try:
                    health = await self.es_client.client.cluster.health(index=index, wait_for_status='yellow')
                    logger.info(f"Index {index} status: {health['status']}")
                except Exception as e:
                    logger.warning(f"Could not verify index {index}: {e}")
                    
            logger.info("Elasticsearch setup completed")
            
        except Exception as e:
            logger.error(f"Elasticsearch setup failed: {e}")
            raise
            
    async def setup_kibana(self):
        """Setup Kibana dashboards and visualizations."""
        logger.info("Setting up Kibana dashboards...")
        
        try:
            # Load dashboard configuration
            dashboard_path = Path("kibana/dashboard-export.json")
            if not dashboard_path.exists():
                logger.warning("Dashboard export file not found, skipping Kibana setup")
                return
                
            with open(dashboard_path, 'r') as f:
                dashboard_config = json.load(f)
                
            # Kibana API endpoint
            kibana_url = "http://localhost:5601"
            
            # Import dashboard objects
            async with aiohttp.ClientSession() as session:
                for obj in dashboard_config['objects']:
                    try:
                        url = f"{kibana_url}/api/saved_objects/{obj['type']}/{obj['id']}"
                        
                        # Create or update object
                        async with session.post(
                            url,
                            json=obj,
                            headers={'Content-Type': 'application/json', 'kbn-xsrf': 'true'}
                        ) as response:
                            if response.status in [200, 201, 409]:  # 409 = already exists
                                logger.info(f"Created/updated {obj['type']}: {obj['id']}")
                            else:
                                logger.warning(f"Failed to create {obj['type']} {obj['id']}: {response.status}")
                                
                    except Exception as e:
                        logger.error(f"Error creating Kibana object {obj['id']}: {e}")
                        
            logger.info("Kibana dashboard setup completed")
            
        except Exception as e:
            logger.error(f"Kibana setup failed: {e}")
            
    async def create_sample_data(self):
        """Create sample data for testing."""
        if not self.config.get('development', {}).get('sample_data', False):
            logger.info("Sample data creation disabled")
            return
            
        logger.info("Creating sample data...")
        
        try:
            # Create sample IOCs
            sample_iocs = [
                IOCModel(
                    value="192.168.1.100",
                    type=IOCType.IP,
                    threat_level=ThreatLevel.HIGH,
                    description="Suspected C2 server",
                    tags=["malware", "c2", "apt"],
                    confidence=85,
                    sources=[IOCSource(name="Test Feed", confidence=85)]
                ),
                IOCModel(
                    value="evil.example.com",
                    type=IOCType.DOMAIN,
                    threat_level=ThreatLevel.MEDIUM,
                    description="Phishing domain",
                    tags=["phishing", "credential_theft"],
                    confidence=70,
                    sources=[IOCSource(name="Test Feed", confidence=70)]
                ),
                IOCModel(
                    value="d41d8cd98f00b204e9800998ecf8427e",
                    type=IOCType.FILE_HASH,
                    hash_type=HashType.MD5,
                    threat_level=ThreatLevel.CRITICAL,
                    description="Known malware sample",
                    tags=["malware", "trojan"],
                    confidence=95,
                    sources=[IOCSource(name="Test Feed", confidence=95)]
                )
            ]
            
            # Store sample IOCs
            for ioc in sample_iocs:
                from src.models.ioc import IOCDocument
                doc = IOCDocument.from_model(ioc)
                await self.es_client.index_document(doc, ioc.value)
                
            logger.info(f"Created {len(sample_iocs)} sample IOCs")
            
            # Create sample threat actors
            sample_actors = [
                ThreatActorModel(
                    name="APT-TEST-1",
                    aliases=["Test Group", "Sample APT"],
                    actor_type=ActorType.APT,
                    sophistication=Sophistication.ADVANCED,
                    motivations=[Motivation.ESPIONAGE],
                    attributed_country="Unknown",
                    description="Sample threat actor for testing",
                    tags=["apt", "espionage"],
                    confidence=80
                )
            ]
            
            # Store sample threat actors
            for actor in sample_actors:
                from src.models.threat_actor import ThreatActorDocument
                doc = ThreatActorDocument.from_model(actor)
                await self.es_client.index_document(doc)
                
            logger.info(f"Created {len(sample_actors)} sample threat actors")
            
            # Create sample alerts
            sample_alerts = [
                AlertModel(
                    title="High Confidence IOC Detected",
                    description="IOC with confidence >= 80%",
                    severity=AlertSeverity.HIGH,
                    category=AlertCategory.IOC_MATCH,
                    rule=AlertRule(
                        id="test_rule",
                        name="Test Rule",
                        description="Test alert rule",
                        severity=AlertSeverity.HIGH
                    ),
                    confidence=85,
                    source_system="threat_intelligence_dashboard",
                    tags=["test", "high_confidence"]
                )
            ]
            
            # Store sample alerts
            for alert in sample_alerts:
                alert.update_risk_score()
                from src.models.alert import AlertDocument
                doc = AlertDocument.from_model(alert)
                await self.es_client.index_document(doc)
                
            logger.info(f"Created {len(sample_alerts)} sample alerts")
            
            # Wait for indexing
            await asyncio.sleep(2)
            
            logger.info("Sample data creation completed")
            
        except Exception as e:
            logger.error(f"Sample data creation failed: {e}")
            
    async def verify_setup(self):
        """Verify the setup is working correctly."""
        logger.info("Verifying setup...")
        
        try:
            # Test Elasticsearch health
            es_health = await self.es_client.health_check()
            logger.info(f"Elasticsearch health: {es_health['status']}")
            
            # Test data queries
            ioc_count = await self.es_client.search_iocs({}, size=0)
            logger.info(f"Total IOCs: {ioc_count['total']}")
            
            actor_count = await self.es_client.search_threat_actors({}, size=0)
            logger.info(f"Total threat actors: {actor_count['total']}")
            
            alert_count = await self.es_client.search_alerts({}, size=0)
            logger.info(f"Total alerts: {alert_count['total']}")
            
            # Test Kibana connectivity
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get("http://localhost:5601/api/status") as response:
                        if response.status == 200:
                            logger.info("Kibana is accessible")
                        else:
                            logger.warning(f"Kibana status: {response.status}")
            except Exception as e:
                logger.warning(f"Could not connect to Kibana: {e}")
                
            logger.info("Setup verification completed")
            
        except Exception as e:
            logger.error(f"Setup verification failed: {e}")
            
    async def run_full_setup(self):
        """Run complete setup process."""
        logger.info("Starting threat intelligence dashboard setup...")
        
        try:
            # Setup Elasticsearch
            await self.setup_elasticsearch()
            
            # Setup Kibana (wait for ES to be ready)
            await asyncio.sleep(10)
            await self.setup_kibana()
            
            # Create sample data if enabled
            await self.create_sample_data()
            
            # Verify everything is working
            await self.verify_setup()
            
            logger.info("=== Setup Complete! ===")
            logger.info("You can now:")
            logger.info("1. Access Kibana at: http://localhost:5601")
            logger.info("2. Access API docs at: http://localhost:8000/docs")
            logger.info("3. Start the collector: python src/collector/main.py")
            logger.info("4. Start the API: python src/api/main.py")
            
        except Exception as e:
            logger.error(f"Setup failed: {e}")
            raise
        finally:
            await self.es_client.close()


async def main():
    """Main setup function."""
    setup_manager = SetupManager()
    await setup_manager.run_full_setup()


if __name__ == "__main__":
    asyncio.run(main())