"""
Processors package for threat intelligence dashboard.
"""

from .enrichment import IOCEnricher
from .deduplication import IOCDeduplicator

__all__ = [
    "IOCEnricher",
    "IOCDeduplicator"
]