"""
Elasticsearch client for threat intelligence data storage and retrieval.
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import NotFoundError, RequestError
from elasticsearch_dsl import AsyncSearch, Q

from src.models.ioc import IOCDocument
from src.models.threat_actor import ThreatActorDocument
from src.models.alert import AlertDocument

logger = logging.getLogger(__name__)


class ElasticsearchClient:
    """Elasticsearch client for threat intelligence dashboard."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Elasticsearch client."""
        self.config = config
        
        # Build connection URL
        host = config.get('host', os.getenv('ELASTICSEARCH_HOST', 'localhost'))
        port = config.get('port', 9200)
        username = config.get('username', '')
        password = config.get('password', '')
        
        if username and password:
            self.es_url = f"http://{username}:{password}@{host}:{port}"
        else:
            self.es_url = f"http://{host}:{port}"
            
        # Initialize client
        self.client = AsyncElasticsearch(
            [self.es_url],
            verify_certs=config.get('ssl_verify', False),
            timeout=config.get('timeout', 30),
            max_retries=config.get('max_retries', 3)
        )
        
    async def initialize_indices(self):
        """Initialize Elasticsearch indices with proper mappings."""
        try:
            # Initialize IOC index
            if not await self.client.indices.exists(index='threat_iocs'):
                ioc_mapping = {
                    "mappings": {
                        "properties": {
                            "value": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "threat_level": {"type": "keyword"},
                            "confidence": {"type": "integer"},
                            "source": {"type": "text"},
                            "tags": {"type": "keyword"},
                            "created_at": {"type": "date"},
                            "last_seen": {"type": "date"},
                            "geo_point": {"type": "geo_point"},
                            "description": {"type": "text"},
                            "related_campaigns": {"type": "keyword"}
                        }
                    }
                }
                await self.client.indices.create(index='threat_iocs', body=ioc_mapping)
                logger.info("Created threat_iocs index")
                
            # Initialize Threat Actor index
            if not await self.client.indices.exists(index='threat_actors'):
                actor_mapping = {
                    "mappings": {
                        "properties": {
                            "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                            "aliases": {"type": "keyword"},
                            "actor_type": {"type": "keyword"},
                            "sophistication": {"type": "keyword"},
                            "attributed_country": {"type": "keyword"},
                            "threat_score": {"type": "float"},
                            "active": {"type": "boolean"},
                            "first_seen": {"type": "date"},
                            "last_seen": {"type": "date"},
                            "description": {"type": "text"},
                            "ttps": {"type": "keyword"},
                            "infrastructure": {
                                "properties": {
                                    "domains": {"type": "keyword"},
                                    "ips": {"type": "ip"},
                                    "c2_servers": {"type": "keyword"}
                                }
                            }
                        }
                    }
                }
                await self.client.indices.create(index='threat_actors', body=actor_mapping)
                logger.info("Created threat_actors index")
                
            # Initialize Alert index
            if not await self.client.indices.exists(index='threat_alerts'):
                alert_mapping = {
                    "mappings": {
                        "properties": {
                            "title": {"type": "text"},
                            "description": {"type": "text"},
                            "severity": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "risk_score": {"type": "float"},
                            "confidence": {"type": "integer"},
                            "created_at": {"type": "date"},
                            "updated_at": {"type": "date"},
                            "source": {"type": "keyword"},
                            "tags": {"type": "keyword"},
                            "mitre_tactics": {"type": "keyword"},
                            "mitre_techniques": {"type": "keyword"},
                            "ioc_matches": {
                                "type": "nested",
                                "properties": {
                                    "ioc_value": {"type": "keyword"},
                                    "ioc_type": {"type": "keyword"},
                                    "match_confidence": {"type": "float"}
                                }
                            }
                        }
                    }
                }
                await self.client.indices.create(index='threat_alerts', body=alert_mapping)
                logger.info("Created threat_alerts index")
                
            # Create index templates for time-based indices
            await self._create_index_templates()
            
        except Exception as e:
            logger.error(f"Error initializing indices: {e}")
            raise
            
    async def _create_index_templates(self):
        """Create index templates for time-based data."""
        try:
            # Template for daily IOC indices
            ioc_template = {
                "index_patterns": ["threat_iocs_*"],
                "template": {
                    "settings": {
                        "number_of_shards": 2,
                        "number_of_replicas": 1,
                        "refresh_interval": "5s"
                    },
                    "mappings": {
                        "properties": {
                            "value": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "threat_level": {"type": "keyword"},
                            "confidence": {"type": "integer"},
                            "created_at": {"type": "date"},
                            "geo_point": {"type": "geo_point"},
                            "tags": {"type": "keyword"}
                        }
                    }
                }
            }
            
            await self.client.indices.put_index_template(
                name="threat_iocs_template",
                body=ioc_template
            )
            
            # Template for daily alert indices
            alert_template = {
                "index_patterns": ["threat_alerts_*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1,
                        "refresh_interval": "1s"
                    },
                    "mappings": {
                        "properties": {
                            "title": {"type": "text"},
                            "severity": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "risk_score": {"type": "float"},
                            "created_at": {"type": "date"},
                            "tags": {"type": "keyword"}
                        }
                    }
                }
            }
            
            await self.client.indices.put_index_template(
                name="threat_alerts_template",
                body=alert_template
            )
            
        except Exception as e:
            logger.error(f"Error creating index templates: {e}")
            
    async def index_document(self, document, doc_id: str = None, index_name: str = None):
        """Index a document in Elasticsearch."""
        try:
            if index_name is None:
                index_name = document._get_index()
                
            if doc_id is None:
                # Auto-generate ID
                response = await document.save(using=self.client)
            else:
                # Use provided ID
                await document.save(using=self.client, id=doc_id)
                
            logger.debug(f"Indexed document in {index_name}")
            
        except Exception as e:
            logger.error(f"Error indexing document: {e}")
            raise
            
    async def get_document(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        """Get a document by ID."""
        try:
            response = await self.client.get(index=index, id=doc_id)
            return response['_source']
        except NotFoundError:
            return None
        except Exception as e:
            logger.error(f"Error getting document: {e}")
            raise
            
    async def search_iocs(self, query: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        """Search IOCs with advanced filtering."""
        try:
            search = AsyncSearch(using=self.client, index='threat_iocs')
            
            # Build query
            if 'value' in query:
                search = search.query('match', value=query['value'])
                
            if 'type' in query:
                search = search.filter('term', type=query['type'])
                
            if 'threat_level' in query:
                search = search.filter('terms', threat_level=query['threat_level'])
                
            if 'confidence_min' in query:
                search = search.filter('range', confidence={'gte': query['confidence_min']})
                
            if 'tags' in query:
                search = search.filter('terms', tags=query['tags'])
                
            if 'date_range' in query:
                date_range = query['date_range']
                search = search.filter('range', created_at={
                    'gte': date_range.get('from'),
                    'lte': date_range.get('to')
                })
                
            # Add sorting and pagination
            search = search.sort('-created_at')[:size]
            
            # Execute search
            response = await search.execute()
            
            return {
                'total': response.hits.total.value,
                'hits': [hit.to_dict() for hit in response.hits],
                'aggregations': response.aggs.to_dict() if hasattr(response, 'aggs') else {}
            }
            
        except Exception as e:
            logger.error(f"Error searching IOCs: {e}")
            raise
            
    async def search_threat_actors(self, query: Dict[str, Any], size: int = 50) -> Dict[str, Any]:
        """Search threat actors."""
        try:
            search = AsyncSearch(using=self.client, index='threat_actors')
            
            # Build query
            if 'name' in query:
                search = search.query('match', name=query['name'])
                
            if 'actor_type' in query:
                search = search.filter('term', actor_type=query['actor_type'])
                
            if 'country' in query:
                search = search.filter('term', attributed_country=query['country'])
                
            if 'active' in query:
                search = search.filter('term', active=query['active'])
                
            # Add sorting
            search = search.sort('-threat_score', '-last_seen')[:size]
            
            # Execute search
            response = await search.execute()
            
            return {
                'total': response.hits.total.value,
                'hits': [hit.to_dict() for hit in response.hits]
            }
            
        except Exception as e:
            logger.error(f"Error searching threat actors: {e}")
            raise
            
    async def search_alerts(self, query: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        """Search security alerts."""
        try:
            search = AsyncSearch(using=self.client, index='threat_alerts')
            
            # Build query
            if 'severity' in query:
                search = search.filter('terms', severity=query['severity'])
                
            if 'status' in query:
                search = search.filter('terms', status=query['status'])
                
            if 'category' in query:
                search = search.filter('term', category=query['category'])
                
            if 'risk_score_min' in query:
                search = search.filter('range', risk_score={'gte': query['risk_score_min']})
                
            if 'date_range' in query:
                date_range = query['date_range']
                search = search.filter('range', created_at={
                    'gte': date_range.get('from'),
                    'lte': date_range.get('to')
                })
                
            # Add sorting
            search = search.sort('-risk_score', '-created_at')[:size]
            
            # Execute search
            response = await search.execute()
            
            return {
                'total': response.hits.total.value,
                'hits': [hit.to_dict() for hit in response.hits]
            }
            
        except Exception as e:
            logger.error(f"Error searching alerts: {e}")
            raise
            
    async def get_ioc_statistics(self) -> Dict[str, Any]:
        """Get IOC statistics and aggregations."""
        try:
            search = AsyncSearch(using=self.client, index='threat_iocs')
            
            # Add aggregations
            search.aggs.bucket('by_type', 'terms', field='type') \
                      .bucket('by_threat_level', 'terms', field='threat_level') \
                      .bucket('by_day', 'date_histogram', field='created_at', calendar_interval='1d') \
                      .metric('avg_confidence', 'avg', field='confidence')
                      
            # Execute with no hits (we only want aggregations)
            search = search[:0]
            response = await search.execute()
            
            return response.aggs.to_dict()
            
        except Exception as e:
            logger.error(f"Error getting IOC statistics: {e}")
            raise
            
    async def get_threat_actor_statistics(self) -> Dict[str, Any]:
        """Get threat actor statistics."""
        try:
            search = AsyncSearch(using=self.client, index='threat_actors')
            
            # Add aggregations
            search.aggs.bucket('by_type', 'terms', field='actor_type') \
                      .bucket('by_country', 'terms', field='attributed_country') \
                      .bucket('by_sophistication', 'terms', field='sophistication') \
                      .metric('avg_threat_score', 'avg', field='threat_score')
                      
            search = search[:0]
            response = await search.execute()
            
            return response.aggs.to_dict()
            
        except Exception as e:
            logger.error(f"Error getting threat actor statistics: {e}")
            raise
            
    async def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        try:
            search = AsyncSearch(using=self.client, index='threat_alerts')
            
            # Add aggregations
            search.aggs.bucket('by_severity', 'terms', field='severity') \
                      .bucket('by_status', 'terms', field='status') \
                      .bucket('by_category', 'terms', field='category') \
                      .bucket('by_hour', 'date_histogram', field='created_at', fixed_interval='1h') \
                      .metric('avg_risk_score', 'avg', field='risk_score')
                      
            search = search[:0]
            response = await search.execute()
            
            return response.aggs.to_dict()
            
        except Exception as e:
            logger.error(f"Error getting alert statistics: {e}")
            raise
            
    async def correlate_iocs(self, ioc_value: str) -> Dict[str, Any]:
        """Find correlations for a specific IOC."""
        try:
            correlations = {
                'related_iocs': [],
                'threat_actors': [],
                'alerts': [],
                'campaigns': []
            }
            
            # Find IOCs with similar tags or sources
            search = AsyncSearch(using=self.client, index='threat_iocs')
            search = search.query('match', value=ioc_value)
            
            response = await search.execute()
            if response.hits:
                ioc_data = response.hits[0].to_dict()
                tags = ioc_data.get('tags', [])
                
                # Find related IOCs with similar tags
                if tags:
                    related_search = AsyncSearch(using=self.client, index='threat_iocs')
                    related_search = related_search.query('terms', tags=tags) \
                                                 .filter('bool', must_not=[Q('match', value=ioc_value)])
                    
                    related_response = await related_search[:20].execute()
                    correlations['related_iocs'] = [hit.to_dict() for hit in related_response.hits]
                    
                # Find threat actors associated with these tags
                actor_search = AsyncSearch(using=self.client, index='threat_actors')
                actor_search = actor_search.query('terms', tags=tags)
                
                actor_response = await actor_search[:10].execute()
                correlations['threat_actors'] = [hit.to_dict() for hit in actor_response.hits]
                
                # Find related alerts
                alert_search = AsyncSearch(using=self.client, index='threat_alerts')
                alert_search = alert_search.query('nested', path='ioc_matches', 
                                                 query=Q('match', **{'ioc_matches.ioc_value': ioc_value}))
                
                alert_response = await alert_search[:10].execute()
                correlations['alerts'] = [hit.to_dict() for hit in alert_response.hits]
                
            return correlations
            
        except Exception as e:
            logger.error(f"Error correlating IOCs: {e}")
            raise
            
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of Elasticsearch cluster."""
        try:
            # Check cluster health
            cluster_health = await self.client.cluster.health()
            
            # Check indices
            indices_health = await self.client.cat.indices(
                index="threat_*",
                format="json"
            )
            
            # Get node info
            nodes_info = await self.client.cat.nodes(format="json")
            
            return {
                'status': 'healthy',
                'cluster': cluster_health,
                'indices': indices_health,
                'nodes': nodes_info
            }
            
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
            
    async def cleanup_old_data(self, retention_days: Dict[str, int]):
        """Clean up old data based on retention policies."""
        try:
            current_time = datetime.utcnow()
            
            # Clean up old IOCs
            if 'iocs' in retention_days:
                cutoff_date = current_time - timedelta(days=retention_days['iocs'])
                
                delete_query = {
                    'query': {
                        'range': {
                            'created_at': {
                                'lt': cutoff_date.isoformat()
                            }
                        }
                    }
                }
                
                result = await self.client.delete_by_query(
                    index='threat_iocs',
                    body=delete_query
                )
                
                logger.info(f"Deleted {result['deleted']} old IOCs")
                
            # Clean up old alerts
            if 'alerts' in retention_days:
                cutoff_date = current_time - timedelta(days=retention_days['alerts'])
                
                delete_query = {
                    'query': {
                        'range': {
                            'created_at': {
                                'lt': cutoff_date.isoformat()
                            }
                        }
                    }
                }
                
                result = await self.client.delete_by_query(
                    index='threat_alerts',
                    body=delete_query
                )
                
                logger.info(f"Deleted {result['deleted']} old alerts")
                
        except Exception as e:
            logger.error(f"Error during data cleanup: {e}")
            
    async def close(self):
        """Close the Elasticsearch client."""
        if self.client:
            await self.client.close()