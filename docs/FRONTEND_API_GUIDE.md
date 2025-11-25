# 🔌 Frontend API Integration Guide

Complete documentation for integrating with the Threat Intelligence Dashboard API endpoints.

## 📋 Table of Contents
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Core API Endpoints](#core-api-endpoints)
- [JavaScript Examples](#javascript-examples)
- [React Components](#react-components)
- [Error Handling](#error-handling)
- [Real-time Updates](#real-time-updates)

## 🚀 Quick Start

### Base Configuration
```javascript
const API_BASE_URL = 'http://localhost:8000';
const API_VERSION = 'v1';

// API Client Setup
class ThreatIntelAPI {
  constructor(baseUrl = API_BASE_URL) {
    this.baseUrl = baseUrl;
    this.apiUrl = `${baseUrl}/api/${API_VERSION}`;
  }

  async request(endpoint, options = {}) {
    const url = `${this.apiUrl}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('API Request failed:', error);
      throw error;
    }
  }
}

const api = new ThreatIntelAPI();
```

## 🔐 Authentication

Currently, the API doesn't require authentication, but prepare for future implementation:

```javascript
class AuthenticatedAPI extends ThreatIntelAPI {
  constructor(baseUrl, apiKey) {
    super(baseUrl);
    this.apiKey = apiKey;
  }

  async request(endpoint, options = {}) {
    const authOptions = {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        ...options.headers
      }
    };
    
    return super.request(endpoint, authOptions);
  }
}
```

## 🔍 Core API Endpoints

### 1. System Health & Status

#### Health Check
```javascript
// GET /health
const checkHealth = async () => {
  try {
    const health = await api.request('/health');
    console.log('System Status:', health.status);
    console.log('Version:', health.version);
    return health;
  } catch (error) {
    console.error('Health check failed:', error);
  }
};

// Usage
checkHealth();
```

#### Detailed Health Check
```javascript
// GET /health/detailed
const getDetailedHealth = async () => {
  const health = await api.request('/health/detailed');
  
  return {
    status: health.status,
    elasticsearch: health.components.elasticsearch.status,
    clusterHealth: health.components.elasticsearch.cluster.status,
    timestamp: health.timestamp
  };
};
```

### 2. IOC (Indicators of Compromise) Management

#### Search IOCs
```javascript
// GET /iocs
const searchIOCs = async (filters = {}) => {
  const params = new URLSearchParams();
  
  // Add filters
  if (filters.type) params.append('type', filters.type);
  if (filters.threatLevel) {
    filters.threatLevel.forEach(level => params.append('threat_level', level));
  }
  if (filters.confidenceMin) params.append('confidence_min', filters.confidenceMin);
  if (filters.tags) {
    filters.tags.forEach(tag => params.append('tags', tag));
  }
  if (filters.fromDate) params.append('from_date', filters.fromDate);
  if (filters.toDate) params.append('to_date', filters.toDate);
  if (filters.size) params.append('size', filters.size);
  if (filters.page) params.append('page', filters.page);

  const endpoint = `/iocs${params.toString() ? '?' + params.toString() : ''}`;
  const result = await api.request(endpoint);
  
  return {
    iocs: result.data,
    total: result.total,
    page: result.page,
    size: result.size,
    aggregations: result.aggregations
  };
};

// Example usage
const maliciousIPs = await searchIOCs({
  type: 'ip',
  threatLevel: ['high', 'critical'],
  confidenceMin: 80,
  size: 50
});
```

#### Get Specific IOC Details
```javascript
// GET /iocs/{ioc_value}
const getIOCDetails = async (iocValue) => {
  const result = await api.request(`/iocs/${encodeURIComponent(iocValue)}`);
  
  return {
    ioc: result.ioc,
    correlations: {
      relatedIOCs: result.correlations.related_iocs,
      threatActors: result.correlations.threat_actors,
      alerts: result.correlations.alerts
    }
  };
};

// Example
const iocDetails = await getIOCDetails('192.168.1.100');
```

#### IOC Statistics
```javascript
// GET /iocs/statistics
const getIOCStatistics = async () => {
  const stats = await api.request('/iocs/statistics');
  
  return {
    byType: stats.by_type.buckets,
    byThreatLevel: stats.by_threat_level.buckets,
    dailyTrends: stats.by_day.buckets,
    avgConfidence: stats.avg_confidence.value
  };
};
```

### 3. Threat Actor Intelligence

#### Search Threat Actors
```javascript
// GET /threat-actors
const searchThreatActors = async (filters = {}) => {
  const params = new URLSearchParams();
  
  if (filters.name) params.append('name', filters.name);
  if (filters.actorType) params.append('actor_type', filters.actorType);
  if (filters.country) params.append('country', filters.country);
  if (filters.active !== undefined) params.append('active', filters.active);
  if (filters.size) params.append('size', filters.size);
  if (filters.page) params.append('page', filters.page);

  const endpoint = `/threat-actors${params.toString() ? '?' + params.toString() : ''}`;
  const result = await api.request(endpoint);
  
  return {
    actors: result.data,
    total: result.total,
    page: result.page,
    size: result.size
  };
};

// Example
const aptGroups = await searchThreatActors({
  actorType: 'apt',
  active: true,
  size: 20
});
```

#### Get Threat Actor Details
```javascript
// GET /threat-actors/{actor_id}
const getThreatActorDetails = async (actorId) => {
  return await api.request(`/threat-actors/${actorId}`);
};
```

#### Threat Actor Statistics
```javascript
// GET /threat-actors/statistics
const getThreatActorStats = async () => {
  const stats = await api.request('/threat-actors/statistics');
  
  return {
    byType: stats.by_type.buckets,
    byCountry: stats.by_country.buckets,
    bySophistication: stats.by_sophistication.buckets,
    avgThreatScore: stats.avg_threat_score.value
  };
};
```

### 4. Security Alerts Management

#### Search Alerts
```javascript
// GET /alerts
const searchAlerts = async (filters = {}) => {
  const params = new URLSearchParams();
  
  if (filters.severity) {
    filters.severity.forEach(sev => params.append('severity', sev));
  }
  if (filters.status) {
    filters.status.forEach(stat => params.append('status', stat));
  }
  if (filters.category) params.append('category', filters.category);
  if (filters.riskScoreMin) params.append('risk_score_min', filters.riskScoreMin);
  if (filters.fromDate) params.append('from_date', filters.fromDate);
  if (filters.toDate) params.append('to_date', filters.toDate);
  if (filters.size) params.append('size', filters.size);
  if (filters.page) params.append('page', filters.page);

  const endpoint = `/alerts${params.toString() ? '?' + params.toString() : ''}`;
  const result = await api.request(endpoint);
  
  return {
    alerts: result.data,
    total: result.total,
    page: result.page,
    size: result.size
  };
};

// Example
const criticalAlerts = await searchAlerts({
  severity: ['high', 'critical'],
  status: ['open', 'investigating'],
  riskScoreMin: 70
});
```

#### Get Alert Details
```javascript
// GET /alerts/{alert_id}
const getAlertDetails = async (alertId) => {
  return await api.request(`/alerts/${alertId}`);
};
```

#### Alert Statistics
```javascript
// GET /alerts/statistics
const getAlertStatistics = async () => {
  const stats = await api.request('/alerts/statistics');
  
  return {
    bySeverity: stats.by_severity.buckets,
    byStatus: stats.by_status.buckets,
    byCategory: stats.by_category.buckets,
    hourlyTrends: stats.by_hour.buckets,
    avgRiskScore: stats.avg_risk_score.value
  };
};
```

### 5. Analytics & Dashboard Data

#### Get Dashboard Data
```javascript
// GET /analytics/dashboard
const getDashboardData = async () => {
  const dashboard = await api.request('/analytics/dashboard');
  
  return {
    statistics: {
      iocs: dashboard.statistics.iocs,
      threatActors: dashboard.statistics.threat_actors,
      alerts: dashboard.statistics.alerts
    },
    recentActivity: {
      iocs: dashboard.recent_activity.iocs,
      alerts: dashboard.recent_activity.alerts
    },
    timestamp: dashboard.timestamp
  };
};
```

#### Get Trend Analysis
```javascript
// GET /analytics/trends
const getTrendAnalysis = async (period = '7d', metric = 'count') => {
  const params = new URLSearchParams({
    period: period,
    metric: metric
  });
  
  return await api.request(`/analytics/trends?${params}`);
};

// Usage examples
const weeklyTrends = await getTrendAnalysis('7d', 'count');
const dailyRiskScores = await getTrendAnalysis('24h', 'risk_score');
```

#### Get IOC Correlations
```javascript
// GET /analytics/correlations/{ioc_value}
const getIOCCorrelations = async (iocValue) => {
  return await api.request(`/analytics/correlations/${encodeURIComponent(iocValue)}`);
};
```

### 6. System Configuration

#### Get Available Enums
```javascript
// GET /enums
const getSystemEnums = async () => {
  const enums = await api.request('/enums');
  
  return {
    iocTypes: enums.ioc_types,
    threatLevels: enums.threat_levels,
    actorTypes: enums.actor_types,
    alertSeverities: enums.alert_severities,
    alertStatuses: enums.alert_statuses
  };
};
```

## 📊 React Components Examples

### IOC Search Component
```jsx
import React, { useState, useEffect } from 'react';

const IOCSearch = () => {
  const [iocs, setIOCs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({
    type: '',
    threatLevel: [],
    size: 50
  });

  const searchIOCs = async () => {
    setLoading(true);
    try {
      const result = await api.searchIOCs(filters);
      setIOCs(result.iocs);
    } catch (error) {
      console.error('Search failed:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    searchIOCs();
  }, [filters]);

  return (
    <div className="ioc-search">
      <div className="search-filters">
        <select 
          value={filters.type}
          onChange={(e) => setFilters({...filters, type: e.target.value})}
        >
          <option value="">All Types</option>
          <option value="ip">IP Address</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="file_hash">File Hash</option>
        </select>
        
        <button onClick={searchIOCs} disabled={loading}>
          {loading ? 'Searching...' : 'Search IOCs'}
        </button>
      </div>

      <div className="results">
        {iocs.map(ioc => (
          <div key={ioc.id} className="ioc-card">
            <h3>{ioc.value}</h3>
            <p>Type: {ioc.type}</p>
            <p>Threat Level: {ioc.threat_level}</p>
            <p>Confidence: {ioc.confidence}%</p>
          </div>
        ))}
      </div>
    </div>
  );
};
```

### Dashboard Statistics Component
```jsx
const DashboardStats = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        const data = await getDashboardData();
        setStats(data);
      } catch (error) {
        console.error('Dashboard load failed:', error);
      } finally {
        setLoading(false);
      }
    };

    loadDashboard();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(loadDashboard, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div>Loading dashboard...</div>;

  return (
    <div className="dashboard-stats">
      <div className="stat-cards">
        <div className="stat-card">
          <h3>Total IOCs</h3>
          <p>{stats.recentActivity.iocs.length}</p>
        </div>
        <div className="stat-card">
          <h3>Active Alerts</h3>
          <p>{stats.recentActivity.alerts.length}</p>
        </div>
      </div>
    </div>
  );
};
```

### Real-time Alert Monitor
```jsx
const AlertMonitor = () => {
  const [alerts, setAlerts] = useState([]);
  const [newAlertCount, setNewAlertCount] = useState(0);

  useEffect(() => {
    const checkForNewAlerts = async () => {
      try {
        const result = await searchAlerts({
          status: ['open'],
          size: 20
        });
        
        const newAlerts = result.alerts.filter(alert => 
          !alerts.find(existing => existing.id === alert.id)
        );
        
        if (newAlerts.length > 0) {
          setNewAlertCount(prev => prev + newAlerts.length);
          setAlerts(result.alerts);
        }
      } catch (error) {
        console.error('Alert check failed:', error);
      }
    };

    // Check every 10 seconds
    const interval = setInterval(checkForNewAlerts, 10000);
    return () => clearInterval(interval);
  }, [alerts]);

  return (
    <div className="alert-monitor">
      <h2>
        Active Alerts 
        {newAlertCount > 0 && (
          <span className="badge">{newAlertCount} new</span>
        )}
      </h2>
      
      <div className="alert-list">
        {alerts.map(alert => (
          <div key={alert.id} className={`alert alert-${alert.severity}`}>
            <h4>{alert.title}</h4>
            <p>{alert.description}</p>
            <small>Risk Score: {alert.risk_score}</small>
          </div>
        ))}
      </div>
    </div>
  );
};
```

## ⚠️ Error Handling

### Comprehensive Error Handler
```javascript
class APIError extends Error {
  constructor(message, status, response) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.response = response;
  }
}

const handleAPIError = (error) => {
  if (error instanceof APIError) {
    switch (error.status) {
      case 404:
        return 'Resource not found';
      case 429:
        return 'Rate limit exceeded. Please try again later.';
      case 500:
        return 'Server error. Please contact support.';
      default:
        return `API Error (${error.status}): ${error.message}`;
    }
  }
  
  if (error.name === 'NetworkError') {
    return 'Network connection failed. Check your internet connection.';
  }
  
  return 'An unexpected error occurred.';
};

// Usage in components
const [error, setError] = useState(null);

try {
  const data = await api.request('/some-endpoint');
} catch (err) {
  setError(handleAPIError(err));
}
```

### Retry Logic
```javascript
const apiWithRetry = async (endpoint, options = {}, maxRetries = 3) => {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await api.request(endpoint, options);
    } catch (error) {
      if (attempt === maxRetries || error.status < 500) {
        throw error;
      }
      
      // Exponential backoff
      const delay = Math.pow(2, attempt) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
};
```

## 🔄 Real-time Updates

### WebSocket Integration (Future Enhancement)
```javascript
class ThreatIntelWebSocket {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.handlers = new Map();
  }

  connect() {
    this.ws = new WebSocket(this.url);
    
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const handler = this.handlers.get(data.type);
      if (handler) {
        handler(data.payload);
      }
    };
  }

  subscribe(eventType, handler) {
    this.handlers.set(eventType, handler);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

// Usage
const ws = new ThreatIntelWebSocket('ws://localhost:8000/ws');
ws.subscribe('new_alert', (alert) => {
  console.log('New alert received:', alert);
});
ws.connect();
```

### Polling for Updates
```javascript
const usePolling = (fetchFunction, interval = 30000) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const poll = async () => {
      try {
        const result = await fetchFunction();
        setData(result);
        setError(null);
      } catch (err) {
        setError(err);
      } finally {
        setLoading(false);
      }
    };

    poll(); // Initial load
    const intervalId = setInterval(poll, interval);
    
    return () => clearInterval(intervalId);
  }, [fetchFunction, interval]);

  return { data, loading, error };
};

// Usage
const { data: alerts, loading, error } = usePolling(
  () => searchAlerts({ status: ['open'] }),
  10000 // Poll every 10 seconds
);
```

## 📱 Mobile-Friendly Considerations

### Responsive Data Loading
```javascript
const useMobileOptimizedAPI = () => {
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768);
  
  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < 768);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const searchIOCs = async (filters) => {
    // Reduce page size on mobile
    const mobileFilters = {
      ...filters,
      size: isMobile ? 20 : 50
    };
    
    return api.searchIOCs(mobileFilters);
  };

  return { searchIOCs, isMobile };
};
```

## 🔧 Development Utilities

### API Mock for Development
```javascript
const createMockAPI = () => {
  return {
    searchIOCs: async (filters) => ({
      iocs: [
        { id: '1', value: '192.168.1.100', type: 'ip', threat_level: 'high' },
        { id: '2', value: 'malicious.com', type: 'domain', threat_level: 'critical' }
      ],
      total: 2,
      page: 1,
      size: 50
    }),
    
    getDashboardData: async () => ({
      statistics: { iocs: {}, threatActors: {}, alerts: {} },
      recentActivity: { iocs: [], alerts: [] },
      timestamp: new Date().toISOString()
    })
  };
};

// Use in development
const api = process.env.NODE_ENV === 'development' 
  ? createMockAPI() 
  : new ThreatIntelAPI();
```

### API Response Validation
```javascript
const validateIOC = (ioc) => {
  const required = ['id', 'value', 'type', 'threat_level'];
  const missing = required.filter(field => !ioc[field]);
  
  if (missing.length > 0) {
    throw new Error(`Invalid IOC: missing fields ${missing.join(', ')}`);
  }
  
  return ioc;
};

const searchIOCs = async (filters) => {
  const result = await api.searchIOCs(filters);
  result.iocs = result.iocs.map(validateIOC);
  return result;
};
```

## 📈 Performance Optimization

### Caching Strategy
```javascript
class CachedAPI extends ThreatIntelAPI {
  constructor(baseUrl, cacheTime = 300000) { // 5 minutes default
    super(baseUrl);
    this.cache = new Map();
    this.cacheTime = cacheTime;
  }

  async request(endpoint, options = {}) {
    const cacheKey = `${endpoint}-${JSON.stringify(options)}`;
    const cached = this.cache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.cacheTime) {
      return cached.data;
    }

    const data = await super.request(endpoint, options);
    this.cache.set(cacheKey, {
      data,
      timestamp: Date.now()
    });
    
    return data;
  }
}
```

### Debounced Search
```javascript
import { debounce } from 'lodash';

const useDebounceSearch = (searchFunction, delay = 500) => {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const debouncedSearch = debounce(async (query) => {
    if (!query) {
      setResults([]);
      return;
    }

    setLoading(true);
    try {
      const data = await searchFunction(query);
      setResults(data);
    } catch (error) {
      console.error('Search error:', error);
    } finally {
      setLoading(false);
    }
  }, delay);

  return { results, loading, search: debouncedSearch };
};
```

This documentation provides comprehensive guidance for integrating frontend applications with your Threat Intelligence Dashboard API. Copy specific sections as needed for your development team!