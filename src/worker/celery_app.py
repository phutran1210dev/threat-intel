"""
Celery application configuration
"""
import os
from celery import Celery
from kombu import Queue

# Redis configuration from environment
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_URL = f'redis://{REDIS_HOST}:6379/0'
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'localhost')
ELASTICSEARCH_URL = f'http://{ELASTICSEARCH_HOST}:9200'

# Create Celery app
app = Celery('threat-intel-worker')

# Configuration
app.conf.update(
    # Broker settings
    broker_url=REDIS_URL,
    result_backend=REDIS_URL,
    
    # Task routing
    task_routes={
        'src.worker.tasks.process_ioc': {'queue': 'ioc_processing'},
        'src.worker.tasks.enrich_ioc': {'queue': 'enrichment'},
        'src.worker.tasks.generate_alert': {'queue': 'alerts'},
        'src.worker.tasks.collect_threat_intel': {'queue': 'collection'},
    },
    
    # Queue definitions
    task_default_queue='default',
    task_queues=(
        Queue('default'),
        Queue('ioc_processing'),
        Queue('enrichment'),
        Queue('alerts'),
        Queue('collection'),
    ),
    
    # Task execution
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    result_expires=3600,
    timezone='UTC',
    enable_utc=True,
    
    # Worker settings
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    
    # Retry settings
    task_default_retry_delay=60,
    task_max_retries=3,
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
)