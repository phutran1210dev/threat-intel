"""
Worker package initialization
"""
from .celery_app import app
from .tasks import *

__all__ = ['app']