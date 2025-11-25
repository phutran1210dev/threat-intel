"""
Celery tasks for threat intelligence processing
"""
import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from celery import Task
from celery.utils.log import get_task_logger

from .celery_app import app
from ..database.elasticsearch_client import ElasticsearchClient
from ..processors.enrichment import IOCEnricher
from ..processors.deduplication import IOCDeduplicator
from ..models.ioc import IOCDocument, IOCModel
from ..models.alert import AlertDocument, AlertModel
from ..alerting.alert_manager import AlertManager

logger = get_task_logger(__name__)


class CallbackTask(Task):
    """Base task class with callbacks"""
    
    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f'Task {task_id} succeeded: {retval}')
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f'Task {task_id} failed: {exc}')
    
    def on_retry(self, exc, task_id, args, kwargs, einfo):
        logger.warning(f'Task {task_id} retry: {exc}')


@app.task(bind=True, base=CallbackTask, name='src.worker.tasks.process_ioc')
def process_ioc(self, ioc_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a new IOC through enrichment and deduplication pipeline
    """
    try:
        logger.info(f'Processing IOC: {ioc_data.get("value", "unknown")}')
        
        # Initialize clients
        es_client = ElasticsearchClient()
        enricher = IOCEnricher()
        deduplicator = IOCDeduplicator()
        
        # Create IOC object
        ioc = IOCModel(**ioc_data)
        
        # Check for duplicates first
        is_duplicate, existing_ioc = asyncio.run(deduplicator.is_duplicate(ioc))
        if is_duplicate:
            logger.info(f'IOC {ioc.value} is duplicate, updating existing entry')
            # Update existing IOC with new information
            existing_ioc.last_seen = datetime.utcnow()
            existing_ioc.hit_count += 1
            existing_ioc.sources.extend([s for s in ioc.sources if s not in existing_ioc.sources])
            
            # Save updated IOC
            doc = IOCDocument(**existing_ioc.to_dict())
            doc.meta.id = existing_ioc.id
            doc.save(using=es_client.client)
            
            return {
                'status': 'updated',
                'ioc_id': existing_ioc.id,
                'message': 'Updated existing IOC'
            }
        
        # Enrich the IOC
        enriched_ioc = asyncio.run(enricher.enrich_ioc(ioc))
        
        # Save to Elasticsearch
        doc = IOCDocument(**enriched_ioc.to_dict())
        doc.save(using=es_client.client)
        
        logger.info(f'Successfully processed IOC: {enriched_ioc.value}')
        
        # Check if IOC matches any alert rules
        if enriched_ioc.risk_score > 7.0:  # High risk IOCs
            generate_alert.delay({
                'title': f'High Risk IOC Detected: {enriched_ioc.value}',
                'alert_type': 'ioc_match',
                'severity': 'high',
                'ioc_type': enriched_ioc.ioc_type,
                'ioc_value': enriched_ioc.value,
                'risk_score': enriched_ioc.risk_score,
                'confidence_score': enriched_ioc.confidence_score,
                'description': f'High risk {enriched_ioc.ioc_type} detected with risk score {enriched_ioc.risk_score}'
            })
        
        return {
            'status': 'success',
            'ioc_id': str(doc.meta.id),
            'risk_score': enriched_ioc.risk_score,
            'enriched_fields': len([k for k, v in enriched_ioc.to_dict().items() if v])
        }
        
    except Exception as exc:
        logger.error(f'Error processing IOC: {exc}')
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@app.task(bind=True, base=CallbackTask, name='src.worker.tasks.enrich_ioc')
def enrich_ioc(self, ioc_id: str, force_update: bool = False) -> Dict[str, Any]:
    """
    Enrich an existing IOC with additional threat intelligence
    """
    try:
        logger.info(f'Enriching IOC: {ioc_id}')
        
        # Initialize clients
        es_client = ElasticsearchClient()
        enricher = IOCEnricher()
        
        # Fetch IOC from Elasticsearch
        doc = IOCDocument.get(id=ioc_id, using=es_client.client)
        ioc = IOC.from_dict(doc.to_dict())
        
        # Skip if recently enriched (unless forced)
        if not force_update and ioc.last_enriched:
            time_since_enriched = datetime.utcnow() - ioc.last_enriched
            if time_since_enriched.total_seconds() < 3600:  # 1 hour
                return {
                    'status': 'skipped',
                    'message': 'Recently enriched'
                }
        
        # Perform enrichment
        enriched_ioc = asyncio.run(enricher.enrich_ioc(ioc))
        enriched_ioc.last_enriched = datetime.utcnow()
        
        # Update document
        for field, value in enriched_ioc.to_dict().items():
            setattr(doc, field, value)
        doc.save(using=es_client.client)
        
        logger.info(f'Successfully enriched IOC: {ioc_id}')
        
        return {
            'status': 'success',
            'ioc_id': ioc_id,
            'enriched_fields': len([k for k, v in enriched_ioc.to_dict().items() if v])
        }
        
    except Exception as exc:
        logger.error(f'Error enriching IOC: {exc}')
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@app.task(bind=True, base=CallbackTask, name='src.worker.tasks.generate_alert')
def generate_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate and send security alert
    """
    try:
        logger.info(f'Generating alert: {alert_data.get("title", "unknown")}')
        
        # Initialize clients
        es_client = ElasticsearchClient()
        alert_manager = AlertManager()
        
        # Create alert object
        alert = Alert(**alert_data)
        alert.created_at = datetime.utcnow()
        alert.updated_at = datetime.utcnow()
        
        # Save to Elasticsearch
        doc = AlertDocument(**alert.to_dict())
        doc.save(using=es_client.client)
        alert_id = str(doc.meta.id)
        
        # Send alert notifications
        asyncio.run(alert_manager.send_alert(alert))
        
        logger.info(f'Successfully generated alert: {alert_id}')
        
        return {
            'status': 'success',
            'alert_id': alert_id,
            'severity': alert.severity,
            'notifications_sent': True
        }
        
    except Exception as exc:
        logger.error(f'Error generating alert: {exc}')
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@app.task(bind=True, base=CallbackTask, name='src.worker.tasks.collect_threat_intel')
def collect_threat_intel(self, source: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Collect threat intelligence from specified source
    """
    try:
        logger.info(f'Starting threat intel collection from: {source}')
        
        from ..collector.main import ThreatIntelligenceCollector
        
        # Initialize collector
        collector = ThreatIntelligenceCollector()
        
        # Run collection based on source
        if source == 'all':
            results = asyncio.run(collector.collect_all_feeds())
        else:
            results = asyncio.run(collector.collect_from_source(source, config or {}))
        
        logger.info(f'Completed threat intel collection from {source}: {results}')
        
        return {
            'status': 'success',
            'source': source,
            'collected_count': results.get('total_collected', 0),
            'processed_count': results.get('total_processed', 0),
            'errors': results.get('errors', [])
        }
        
    except Exception as exc:
        logger.error(f'Error collecting threat intel from {source}: {exc}')
        raise self.retry(exc=exc, countdown=300, max_retries=3)


@app.task(bind=True, base=CallbackTask)
def bulk_process_iocs(self, ioc_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process multiple IOCs in batch
    """
    try:
        logger.info(f'Bulk processing {len(ioc_list)} IOCs')
        
        results = {
            'processed': 0,
            'failed': 0,
            'duplicates': 0,
            'errors': []
        }
        
        # Process each IOC
        for ioc_data in ioc_list:
            try:
                result = process_ioc.delay(ioc_data).get(timeout=60)
                if result['status'] in ['success', 'updated']:
                    results['processed'] += 1
                    if result['status'] == 'updated':
                        results['duplicates'] += 1
            except Exception as e:
                results['failed'] += 1
                results['errors'].append(str(e))
        
        logger.info(f'Bulk processing completed: {results}')
        return results
        
    except Exception as exc:
        logger.error(f'Error in bulk processing: {exc}')
        raise self.retry(exc=exc, countdown=60, max_retries=2)


@app.task(bind=True, base=CallbackTask)
def cleanup_old_data(self, days: int = 30) -> Dict[str, Any]:
    """
    Cleanup old data from Elasticsearch
    """
    try:
        logger.info(f'Starting cleanup of data older than {days} days')
        
        es_client = ElasticsearchClient()
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Query for old documents
        query = {
            'query': {
                'range': {
                    'created_at': {
                        'lt': cutoff_date.isoformat()
                    }
                }
            }
        }
        
        # Delete old IOCs
        ioc_result = es_client.client.delete_by_query(
            index='iocs',
            body=query
        )
        
        # Delete old alerts (keep longer - 90 days)
        alert_cutoff = datetime.utcnow() - timedelta(days=90)
        alert_query = {
            'query': {
                'range': {
                    'created_at': {
                        'lt': alert_cutoff.isoformat()
                    }
                }
            }
        }
        
        alert_result = es_client.client.delete_by_query(
            index='alerts',
            body=alert_query
        )
        
        results = {
            'status': 'success',
            'iocs_deleted': ioc_result.get('deleted', 0),
            'alerts_deleted': alert_result.get('deleted', 0),
            'cutoff_date': cutoff_date.isoformat()
        }
        
        logger.info(f'Cleanup completed: {results}')
        return results
        
    except Exception as exc:
        logger.error(f'Error during cleanup: {exc}')
        raise self.retry(exc=exc, countdown=300, max_retries=2)


# Periodic tasks configuration
from celery.schedules import crontab

app.conf.beat_schedule = {
    # Collect threat intel every hour
    'collect-threat-intel': {
        'task': 'src.worker.tasks.collect_threat_intel',
        'schedule': crontab(minute=0),  # Every hour
        'args': ('all',)
    },
    
    # Cleanup old data daily at 2 AM
    'cleanup-old-data': {
        'task': 'src.worker.tasks.cleanup_old_data',
        'schedule': crontab(hour=2, minute=0),  # 2:00 AM daily
        'args': (30,)  # 30 days
    },
}

app.conf.timezone = 'UTC'