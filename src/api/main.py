"""
FastAPI application for threat intelligence dashboard API.
Provides REST endpoints for IOCs, threat actors, alerts, and analytics.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException, Depends, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import yaml
from pathlib import Path as FilePath

from src.database.elasticsearch_client import ElasticsearchClient
from src.models.ioc import IOCModel, IOCType, ThreatLevel
from src.models.threat_actor import ThreatActorModel, ActorType
from src.models.alert import AlertModel, AlertSeverity, AlertStatus

# Initialize FastAPI app
app = FastAPI(
    title="Threat Intelligence Dashboard API",
    description="API for threat intelligence data aggregation and analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Load configuration
config_path = FilePath("config/api.yaml")
with open(config_path, 'r') as f:
    config = yaml.safe_load(f)

# Initialize Elasticsearch client
es_client = ElasticsearchClient(config['elasticsearch'])

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config['api']['cors_origins'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    await es_client.initialize_indices()


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown."""
    await es_client.close()


# Health Check Endpoints

@app.get("/health")
async def health_check():
    """API health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/health/detailed")
async def detailed_health_check():
    """Detailed health check including all components."""
    es_health = await es_client.health_check()
    
    return {
        "status": "healthy" if es_health["status"] == "healthy" else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "elasticsearch": es_health,
            "api": {"status": "healthy"}
        }
    }


# IOC Endpoints

@app.get("/api/v1/iocs", response_model=Dict[str, Any])
async def search_iocs(
    value: Optional[str] = Query(None, description="IOC value to search"),
    type: Optional[IOCType] = Query(None, description="IOC type filter"),
    threat_level: Optional[List[ThreatLevel]] = Query(None, description="Threat level filter"),
    confidence_min: Optional[int] = Query(None, ge=0, le=100, description="Minimum confidence score"),
    tags: Optional[List[str]] = Query(None, description="Tags filter"),
    from_date: Optional[datetime] = Query(None, description="Start date filter"),
    to_date: Optional[datetime] = Query(None, description="End date filter"),
    size: int = Query(100, ge=1, le=1000, description="Number of results"),
    page: int = Query(1, ge=1, description="Page number")
):
    """Search IOCs with filters."""
    try:
        query = {}
        
        if value:
            query['value'] = value
        if type:
            query['type'] = type.value
        if threat_level:
            query['threat_level'] = [level.value for level in threat_level]
        if confidence_min is not None:
            query['confidence_min'] = confidence_min
        if tags:
            query['tags'] = tags
        if from_date or to_date:
            query['date_range'] = {}
            if from_date:
                query['date_range']['from'] = from_date.isoformat()
            if to_date:
                query['date_range']['to'] = to_date.isoformat()
                
        # Calculate offset for pagination
        offset = (page - 1) * size
        
        results = await es_client.search_iocs(query, size + offset)
        
        # Apply pagination
        hits = results['hits'][offset:offset + size]
        
        return {
            "total": results['total'],
            "page": page,
            "size": size,
            "data": hits,
            "aggregations": results.get('aggregations', {})
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/iocs/{ioc_value}")
async def get_ioc_details(
    ioc_value: str = Path(..., description="IOC value to retrieve")
):
    """Get detailed information about a specific IOC."""
    try:
        # Get IOC details
        query = {'value': ioc_value}
        results = await es_client.search_iocs(query, size=1)
        
        if not results['hits']:
            raise HTTPException(status_code=404, detail="IOC not found")
            
        ioc_data = results['hits'][0]
        
        # Get correlations
        correlations = await es_client.correlate_iocs(ioc_value)
        
        return {
            "ioc": ioc_data,
            "correlations": correlations
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/iocs/statistics")
async def get_ioc_statistics():
    """Get IOC statistics and trends."""
    try:
        stats = await es_client.get_ioc_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Threat Actor Endpoints

@app.get("/api/v1/threat-actors")
async def search_threat_actors(
    name: Optional[str] = Query(None, description="Actor name to search"),
    actor_type: Optional[ActorType] = Query(None, description="Actor type filter"),
    country: Optional[str] = Query(None, description="Attributed country filter"),
    active: Optional[bool] = Query(None, description="Active status filter"),
    size: int = Query(50, ge=1, le=500, description="Number of results"),
    page: int = Query(1, ge=1, description="Page number")
):
    """Search threat actors."""
    try:
        query = {}
        
        if name:
            query['name'] = name
        if actor_type:
            query['actor_type'] = actor_type.value
        if country:
            query['country'] = country
        if active is not None:
            query['active'] = active
            
        # Calculate offset for pagination
        offset = (page - 1) * size
        
        results = await es_client.search_threat_actors(query, size + offset)
        
        # Apply pagination
        hits = results['hits'][offset:offset + size]
        
        return {
            "total": results['total'],
            "page": page,
            "size": size,
            "data": hits
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/threat-actors/{actor_id}")
async def get_threat_actor_details(
    actor_id: str = Path(..., description="Threat actor ID")
):
    """Get detailed information about a specific threat actor."""
    try:
        actor_data = await es_client.get_document('threat_actors', actor_id)
        
        if not actor_data:
            raise HTTPException(status_code=404, detail="Threat actor not found")
            
        return actor_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/threat-actors/statistics")
async def get_threat_actor_statistics():
    """Get threat actor statistics."""
    try:
        stats = await es_client.get_threat_actor_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Alert Endpoints

@app.get("/api/v1/alerts")
async def search_alerts(
    severity: Optional[List[AlertSeverity]] = Query(None, description="Severity filter"),
    status: Optional[List[AlertStatus]] = Query(None, description="Status filter"),
    category: Optional[str] = Query(None, description="Category filter"),
    risk_score_min: Optional[float] = Query(None, ge=0, le=100, description="Minimum risk score"),
    from_date: Optional[datetime] = Query(None, description="Start date filter"),
    to_date: Optional[datetime] = Query(None, description="End date filter"),
    size: int = Query(100, ge=1, le=1000, description="Number of results"),
    page: int = Query(1, ge=1, description="Page number")
):
    """Search security alerts."""
    try:
        query = {}
        
        if severity:
            query['severity'] = [sev.value for sev in severity]
        if status:
            query['status'] = [stat.value for stat in status]
        if category:
            query['category'] = category
        if risk_score_min is not None:
            query['risk_score_min'] = risk_score_min
        if from_date or to_date:
            query['date_range'] = {}
            if from_date:
                query['date_range']['from'] = from_date.isoformat()
            if to_date:
                query['date_range']['to'] = to_date.isoformat()
                
        # Calculate offset for pagination
        offset = (page - 1) * size
        
        results = await es_client.search_alerts(query, size + offset)
        
        # Apply pagination
        hits = results['hits'][offset:offset + size]
        
        return {
            "total": results['total'],
            "page": page,
            "size": size,
            "data": hits
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert_details(
    alert_id: str = Path(..., description="Alert ID")
):
    """Get detailed information about a specific alert."""
    try:
        alert_data = await es_client.get_document('threat_alerts', alert_id)
        
        if not alert_data:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        return alert_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/alerts/statistics")
async def get_alert_statistics():
    """Get alert statistics and trends."""
    try:
        stats = await es_client.get_alert_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Analytics Endpoints

@app.get("/api/v1/analytics/dashboard")
async def get_dashboard_data():
    """Get comprehensive dashboard data."""
    try:
        # Get statistics from all data sources
        ioc_stats = await es_client.get_ioc_statistics()
        actor_stats = await es_client.get_threat_actor_statistics()
        alert_stats = await es_client.get_alert_statistics()
        
        # Get recent activity
        recent_query = {
            'date_range': {
                'from': (datetime.utcnow() - timedelta(hours=24)).isoformat()
            }
        }
        
        recent_iocs = await es_client.search_iocs(recent_query, size=10)
        recent_alerts = await es_client.search_alerts(recent_query, size=10)
        
        return {
            "statistics": {
                "iocs": ioc_stats,
                "threat_actors": actor_stats,
                "alerts": alert_stats
            },
            "recent_activity": {
                "iocs": recent_iocs['hits'],
                "alerts": recent_alerts['hits']
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/analytics/trends")
async def get_trends(
    period: str = Query("7d", regex="^(1h|24h|7d|30d)$", description="Time period"),
    metric: str = Query("count", regex="^(count|confidence|risk_score)$", description="Metric to analyze")
):
    """Get trend analysis for specified period."""
    try:
        # Calculate date range based on period
        if period == "1h":
            start_date = datetime.utcnow() - timedelta(hours=1)
            interval = "1m"
        elif period == "24h":
            start_date = datetime.utcnow() - timedelta(hours=24)
            interval = "1h"
        elif period == "7d":
            start_date = datetime.utcnow() - timedelta(days=7)
            interval = "6h"
        else:  # 30d
            start_date = datetime.utcnow() - timedelta(days=30)
            interval = "1d"
            
        # This would implement trend analysis logic
        # For now, return a placeholder structure
        return {
            "period": period,
            "metric": metric,
            "start_date": start_date.isoformat(),
            "interval": interval,
            "trends": {
                "iocs": [],
                "alerts": [],
                "threat_score": []
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/analytics/correlations/{ioc_value}")
async def get_ioc_correlations(
    ioc_value: str = Path(..., description="IOC value for correlation analysis")
):
    """Get correlation analysis for a specific IOC."""
    try:
        correlations = await es_client.correlate_iocs(ioc_value)
        return correlations
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Utility Endpoints

@app.get("/api/v1/enums")
async def get_enums():
    """Get all enumeration values for the API."""
    return {
        "ioc_types": [ioc_type.value for ioc_type in IOCType],
        "threat_levels": [level.value for level in ThreatLevel],
        "actor_types": [actor_type.value for actor_type in ActorType],
        "alert_severities": [severity.value for severity in AlertSeverity],
        "alert_statuses": [status.value for status in AlertStatus]
    }


# Error Handlers

@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=404,
        content={"error": "Not found", "detail": str(exc)}
    )


@app.exception_handler(500)
async def internal_error_handler(request, exc):
    """Handle 500 errors."""
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )


if __name__ == "__main__":
    import uvicorn
    
    api_config = config['api']
    uvicorn.run(
        app,
        host=api_config['host'],
        port=api_config['port'],
        workers=api_config['workers'],
        log_level=api_config['log_level']
    )