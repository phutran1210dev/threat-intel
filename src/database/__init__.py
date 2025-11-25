"""
Database package for threat intelligence dashboard.
"""

from .elasticsearch_client import ElasticsearchClient

__all__ = [
    "ElasticsearchClient"
]