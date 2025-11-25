# 📱 React Integration Examples

Complete React components and hooks for integrating with the Threat Intelligence API.

## 🏗️ Project Setup

### Install Dependencies

```bash
npm install axios react-query @types/node
# or
yarn add axios react-query @types/node
```

### API Client Configuration

```typescript
// src/api/client.ts
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for authentication
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);
```

## 📊 Dashboard Components

### Main Dashboard

```tsx
// src/components/ThreatDashboard.tsx
import React, { useEffect, useState } from 'react';
import { useQuery } from 'react-query';
import { apiClient } from '../api/client';

interface DashboardData {
  total_iocs: number;
  high_threat_iocs: number;
  active_threat_actors: number;
  recent_alerts: number;
  ioc_types: Record<string, number>;
  threat_levels: Record<string, number>;
}

const ThreatDashboard: React.FC = () => {
  const { data, isLoading, error, refetch } = useQuery<DashboardData>(
    'dashboard',
    () => apiClient.get('/api/v1/analytics/dashboard').then(res => res.data),
    {
      refetchInterval: 30000, // Refresh every 30 seconds
      staleTime: 15000,
    }
  );

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <h3 className="text-red-800 font-medium">Failed to load dashboard data</h3>
        <button 
          onClick={() => refetch()}
          className="mt-2 bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      {/* Summary Cards */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium">Total IOCs</h3>
        <p className="text-3xl font-bold text-gray-900">{data?.total_iocs || 0}</p>
      </div>
      
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium">High Threat IOCs</h3>
        <p className="text-3xl font-bold text-red-600">{data?.high_threat_iocs || 0}</p>
      </div>
      
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium">Active Threat Actors</h3>
        <p className="text-3xl font-bold text-orange-600">{data?.active_threat_actors || 0}</p>
      </div>
      
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium">Recent Alerts</h3>
        <p className="text-3xl font-bold text-yellow-600">{data?.recent_alerts || 0}</p>
      </div>

      {/* IOC Types Chart */}
      <div className="col-span-full bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-medium mb-4">IOC Types Distribution</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Object.entries(data?.ioc_types || {}).map(([type, count]) => (
            <div key={type} className="text-center">
              <p className="text-2xl font-bold text-blue-600">{count}</p>
              <p className="text-sm text-gray-600 capitalize">{type}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ThreatDashboard;
```

### IOC Search Component

```tsx
// src/components/IOCSearch.tsx
import React, { useState } from 'react';
import { useQuery } from 'react-query';
import { apiClient } from '../api/client';

interface IOC {
  id: string;
  value: string;
  type: string;
  threat_level: string;
  source: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
}

interface SearchParams {
  query?: string;
  type?: string;
  threat_level?: string;
  source?: string;
  page?: number;
  size?: number;
}

const IOCSearch: React.FC = () => {
  const [searchParams, setSearchParams] = useState<SearchParams>({
    page: 1,
    size: 20
  });
  const [searchInput, setSearchInput] = useState('');

  const { data, isLoading, error } = useQuery(
    ['iocs', searchParams],
    () => apiClient.get('/api/v1/iocs', { params: searchParams }).then(res => res.data),
    {
      keepPreviousData: true,
    }
  );

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams(prev => ({
      ...prev,
      query: searchInput,
      page: 1
    }));
  };

  const handleFilterChange = (field: keyof SearchParams, value: string) => {
    setSearchParams(prev => ({
      ...prev,
      [field]: value || undefined,
      page: 1
    }));
  };

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <h2 className="text-lg font-medium text-gray-900">IOC Search</h2>
        
        {/* Search Form */}
        <form onSubmit={handleSearch} className="mt-4">
          <div className="flex gap-4 mb-4">
            <div className="flex-1">
              <input
                type="text"
                placeholder="Search IOCs (IP, domain, hash, etc.)"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <button
              type="submit"
              className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              Search
            </button>
          </div>

          {/* Filters */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <select
              value={searchParams.type || ''}
              onChange={(e) => handleFilterChange('type', e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
              <option value="url">URL</option>
            </select>

            <select
              value={searchParams.threat_level || ''}
              onChange={(e) => handleFilterChange('threat_level', e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Threat Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              value={searchParams.source || ''}
              onChange={(e) => handleFilterChange('source', e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Sources</option>
              <option value="misp">MISP</option>
              <option value="otx">AlienVault OTX</option>
              <option value="virustotal">VirusTotal</option>
              <option value="manual">Manual Entry</option>
            </select>
          </div>
        </form>
      </div>

      {/* Results */}
      <div className="p-6">
        {isLoading ? (
          <div className="text-center py-8">Loading...</div>
        ) : error ? (
          <div className="text-center py-8 text-red-600">
            Error loading IOCs. Please try again.
          </div>
        ) : (
          <div className="space-y-4">
            {data?.items?.map((ioc: IOC) => (
              <div key={ioc.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <h4 className="font-medium text-gray-900">{ioc.value}</h4>
                    <div className="flex gap-4 text-sm text-gray-600 mt-1">
                      <span>Type: {ioc.type}</span>
                      <span>Source: {ioc.source}</span>
                      <span>First Seen: {new Date(ioc.first_seen).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`inline-block px-2 py-1 text-xs font-medium rounded-full ${
                      ioc.threat_level === 'critical' ? 'bg-red-100 text-red-800' :
                      ioc.threat_level === 'high' ? 'bg-orange-100 text-orange-800' :
                      ioc.threat_level === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {ioc.threat_level}
                    </span>
                  </div>
                </div>
                {ioc.tags.length > 0 && (
                  <div className="mt-2">
                    {ioc.tags.map(tag => (
                      <span key={tag} className="inline-block bg-gray-100 text-gray-700 px-2 py-1 text-xs rounded mr-2">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            
            {/* Pagination */}
            {data?.total > searchParams.size && (
              <div className="flex justify-center mt-6">
                <nav className="flex gap-2">
                  <button
                    onClick={() => setSearchParams(prev => ({ ...prev, page: Math.max(1, prev.page! - 1) }))}
                    disabled={searchParams.page === 1}
                    className="px-3 py-2 border border-gray-300 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
                  >
                    Previous
                  </button>
                  <span className="px-3 py-2 text-gray-700">
                    Page {searchParams.page} of {Math.ceil(data.total / searchParams.size)}
                  </span>
                  <button
                    onClick={() => setSearchParams(prev => ({ ...prev, page: prev.page! + 1 }))}
                    disabled={searchParams.page >= Math.ceil(data.total / searchParams.size)}
                    className="px-3 py-2 border border-gray-300 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
                  >
                    Next
                  </button>
                </nav>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default IOCSearch;
```

### Alert Management Component

```tsx
// src/components/AlertManagement.tsx
import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { apiClient } from '../api/client';

interface Alert {
  id: string;
  title: string;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
  description: string;
  source: string;
  related_iocs: string[];
}

const AlertManagement: React.FC = () => {
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery(
    ['alerts', statusFilter, severityFilter],
    () => {
      const params: Record<string, string> = {};
      if (statusFilter !== 'all') params.status = statusFilter;
      if (severityFilter !== 'all') params.severity = severityFilter;
      return apiClient.get('/api/v1/alerts', { params }).then(res => res.data);
    },
    {
      refetchInterval: 30000,
    }
  );

  const updateAlertMutation = useMutation(
    ({ id, status }: { id: string; status: string }) =>
      apiClient.patch(`/api/v1/alerts/${id}`, { status }),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('alerts');
      },
    }
  );

  const handleStatusUpdate = (alertId: string, newStatus: string) => {
    updateAlertMutation.mutate({ id: alertId, status: newStatus });
  };

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <h2 className="text-lg font-medium text-gray-900">Security Alerts</h2>
        
        {/* Filters */}
        <div className="flex gap-4 mt-4">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <div className="p-6">
        {isLoading ? (
          <div className="text-center py-8">Loading alerts...</div>
        ) : error ? (
          <div className="text-center py-8 text-red-600">
            Error loading alerts. Please try again.
          </div>
        ) : (
          <div className="space-y-4">
            {data?.items?.map((alert: Alert) => (
              <div key={alert.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h4 className="font-medium text-gray-900">{alert.title}</h4>
                    <p className="text-gray-600 text-sm mt-1">{alert.description}</p>
                    <div className="flex gap-4 text-sm text-gray-500 mt-2">
                      <span>Source: {alert.source}</span>
                      <span>Created: {new Date(alert.created_at).toLocaleString()}</span>
                      <span>IOCs: {alert.related_iocs.length}</span>
                    </div>
                  </div>
                  
                  <div className="flex gap-2 items-center">
                    <span className={`inline-block px-2 py-1 text-xs font-medium rounded-full ${
                      alert.severity === 'critical' ? 'bg-red-100 text-red-800' :
                      alert.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                      alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {alert.severity}
                    </span>
                    
                    <select
                      value={alert.status}
                      onChange={(e) => handleStatusUpdate(alert.id, e.target.value)}
                      className={`px-2 py-1 text-xs border border-gray-300 rounded ${
                        updateAlertMutation.isLoading ? 'opacity-50 cursor-not-allowed' : ''
                      }`}
                      disabled={updateAlertMutation.isLoading}
                    >
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="resolved">Resolved</option>
                      <option value="closed">Closed</option>
                    </select>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertManagement;
```

## 🔗 Custom Hooks

### API Hook for IOC Operations

```tsx
// src/hooks/useIOCs.ts
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { apiClient } from '../api/client';

export interface IOCSearchParams {
  query?: string;
  type?: string;
  threat_level?: string;
  source?: string;
  page?: number;
  size?: number;
}

export const useIOCs = (params: IOCSearchParams = {}) => {
  return useQuery(
    ['iocs', params],
    () => apiClient.get('/api/v1/iocs', { params }).then(res => res.data),
    {
      keepPreviousData: true,
      staleTime: 5 * 60 * 1000, // 5 minutes
    }
  );
};

export const useIOCDetail = (iocId: string) => {
  return useQuery(
    ['ioc', iocId],
    () => apiClient.get(`/api/v1/iocs/${iocId}`).then(res => res.data),
    {
      enabled: !!iocId,
    }
  );
};

export const useCreateIOC = () => {
  const queryClient = useQueryClient();
  
  return useMutation(
    (iocData: any) => apiClient.post('/api/v1/iocs', iocData),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('iocs');
      },
    }
  );
};
```

### Real-time Updates Hook

```tsx
// src/hooks/useRealTimeUpdates.ts
import { useEffect, useState } from 'react';
import { useQueryClient } from 'react-query';

export const useRealTimeUpdates = () => {
  const [isConnected, setIsConnected] = useState(false);
  const queryClient = useQueryClient();

  useEffect(() => {
    // WebSocket connection for real-time updates
    const ws = new WebSocket('ws://localhost:8000/ws/updates');
    
    ws.onopen = () => {
      setIsConnected(true);
      console.log('WebSocket connected');
    };
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      switch (data.type) {
        case 'new_ioc':
          queryClient.invalidateQueries('iocs');
          queryClient.invalidateQueries('dashboard');
          break;
        case 'new_alert':
          queryClient.invalidateQueries('alerts');
          queryClient.invalidateQueries('dashboard');
          break;
        case 'threat_actor_update':
          queryClient.invalidateQueries('threat-actors');
          break;
        default:
          console.log('Unknown update type:', data.type);
      }
    };
    
    ws.onclose = () => {
      setIsConnected(false);
      console.log('WebSocket disconnected');
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setIsConnected(false);
    };

    return () => {
      ws.close();
    };
  }, [queryClient]);

  return { isConnected };
};
```

## 🎨 Styling with Tailwind CSS

Add these utility classes to your Tailwind configuration:

```javascript
// tailwind.config.js
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        threat: {
          critical: '#dc2626',
          high: '#ea580c', 
          medium: '#d97706',
          low: '#059669',
        }
      }
    },
  },
  plugins: [],
}
```

## 🔧 Environment Configuration

```bash
# .env.local
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
REACT_APP_REFRESH_INTERVAL=30000
```

## 🚀 Usage Example

```tsx
// src/App.tsx
import React from 'react';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';
import ThreatDashboard from './components/ThreatDashboard';
import IOCSearch from './components/IOCSearch';
import AlertManagement from './components/AlertManagement';
import { useRealTimeUpdates } from './hooks/useRealTimeUpdates';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      refetchOnWindowFocus: false,
    },
  },
});

const AppContent: React.FC = () => {
  const { isConnected } = useRealTimeUpdates();
  
  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <h1 className="text-2xl font-bold text-gray-900">
              Threat Intelligence Dashboard
            </h1>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></div>
              <span className="text-sm text-gray-600">
                {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        <ThreatDashboard />
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">
          <IOCSearch />
          <AlertManagement />
        </div>
      </main>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  );
};

export default App;
```

This React integration provides a complete frontend solution with real-time updates, proper state management, and a responsive UI for your threat intelligence platform!