#!/bin/bash

# Threat Intelligence Dashboard Setup Script
# This script sets up the complete threat intelligence dashboard

set -e

echo "🔍 Threat Intelligence Dashboard Setup"
echo "======================================"

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Function to check if port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "⚠️  Port $port is already in use. Please stop the service using this port."
        return 1
    fi
    return 0
}

# Check required ports
echo "🔍 Checking required ports..."
check_port 9200 || exit 1  # Elasticsearch
check_port 5601 || exit 1  # Kibana
check_port 8000 || exit 1  # API
check_port 6379 || exit 1  # Redis

echo "✅ All required ports are available"

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating environment file..."
    cat > .env << EOF
# Elasticsearch Configuration
ES_HOST=elasticsearch
ES_PORT=9200

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Development mode
DEBUG=false
SAMPLE_DATA=true
EOF
    echo "✅ Environment file created"
fi

# Create logs directory
mkdir -p logs
echo "✅ Logs directory created"

# Build and start services
echo "🐳 Building and starting Docker containers..."
if command -v docker compose &> /dev/null; then
    docker compose up -d --build
else
    docker-compose up -d --build
fi

# Wait for Elasticsearch to be ready
echo "⏳ Waiting for Elasticsearch to be ready..."
timeout=300
counter=0
while ! curl -s http://localhost:9200/_cluster/health &> /dev/null; do
    if [ $counter -ge $timeout ]; then
        echo "❌ Elasticsearch failed to start within $timeout seconds"
        exit 1
    fi
    sleep 5
    counter=$((counter + 5))
    echo "   Waiting... ($counter/$timeout seconds)"
done

echo "✅ Elasticsearch is ready"

# Wait for Kibana to be ready
echo "⏳ Waiting for Kibana to be ready..."
counter=0
while ! curl -s http://localhost:5601/api/status &> /dev/null; do
    if [ $counter -ge $timeout ]; then
        echo "❌ Kibana failed to start within $timeout seconds"
        exit 1
    fi
    sleep 5
    counter=$((counter + 5))
    echo "   Waiting... ($counter/$timeout seconds)"
done

echo "✅ Kibana is ready"

# Setup Python environment (for running setup script)
if [ ! -d "venv" ]; then
    echo "🐍 Creating Python virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

echo "📦 Installing Python dependencies..."
source venv/bin/activate
pip install -r requirements.txt &> /dev/null
echo "✅ Dependencies installed"

# Run setup script to initialize indices and sample data
echo "🔧 Initializing Elasticsearch indices and sample data..."
python scripts/setup_indices.py

echo ""
echo "🎉 Threat Intelligence Dashboard Setup Complete!"
echo ""
echo "📊 Access Points:"
echo "   • Kibana Dashboard: http://localhost:5601"
echo "   • API Documentation: http://localhost:8000/docs"
echo "   • API Health Check: http://localhost:8000/health"
echo ""
echo "🚀 Services Status:"
echo "   • Elasticsearch: http://localhost:9200"
echo "   • Kibana: http://localhost:5601"
echo "   • API Server: http://localhost:8000"
echo "   • Redis: localhost:6379"
echo ""
echo "📖 Next Steps:"
echo "   1. Configure threat intelligence feeds in config/settings.yaml"
echo "   2. Add your API keys for threat intelligence sources"
echo "   3. Configure alerting channels (email, Slack, Discord)"
echo "   4. Access Kibana to view dashboards and visualizations"
echo ""
echo "🔧 Management Commands:"
echo "   • View logs: docker-compose logs -f [service]"
echo "   • Stop services: docker-compose down"
echo "   • Restart: docker-compose restart"
echo "   • Update: git pull && docker-compose up -d --build"
echo ""

# Deactivate virtual environment
deactivate