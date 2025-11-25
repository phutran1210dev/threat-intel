#!/bin/bash

# 🚀 Threat Intelligence Dashboard - Quick Start Script
# This script will setup and run the complete threat intelligence platform

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if port is available
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        return 1
    else
        return 0
    fi
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Docker
    if ! command_exists docker; then
        print_error "Docker is not installed. Please install Docker first."
        echo "Visit: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command_exists docker-compose && ! docker compose version >/dev/null 2>&1; then
        print_error "Docker Compose is not available. Please install Docker Compose."
        exit 1
    fi
    
    # Check required ports
    ports=(5601 8000 9200 6379)
    for port in "${ports[@]}"; do
        if ! check_port $port; then
            print_warning "Port $port is already in use. This may cause conflicts."
        fi
    done
    
    print_success "Prerequisites check completed"
}

# Setup environment
setup_environment() {
    print_status "Setting up environment..."
    
    # Create .env if it doesn't exist
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            print_success "Created .env from .env.example"
        else
            print_warning ".env.example not found, creating minimal .env"
            cat > .env << EOF
# Threat Intelligence Dashboard Configuration
NODE_ENV=development
LOG_LEVEL=INFO

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=2

# Elasticsearch Configuration
ELASTICSEARCH_URL=http://elasticsearch:9200

# Redis Configuration  
REDIS_URL=redis://redis:6379

# Security (Change in production!)
API_SECRET_KEY=dev-secret-key-change-in-production
EOF
        fi
    else
        print_success ".env file already exists"
    fi
}

# Start services
start_services() {
    print_status "Starting threat intelligence services..."
    
    # Pull latest images
    print_status "Pulling Docker images..."
    if command_exists docker-compose; then
        docker-compose pull
    else
        docker compose pull
    fi
    
    # Start services in background
    print_status "Starting services in background..."
    if command_exists docker-compose; then
        docker-compose up -d
    else
        docker compose up -d
    fi
    
    print_success "Services started successfully"
}

# Wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    # Wait for Elasticsearch
    print_status "Waiting for Elasticsearch..."
    for i in {1..30}; do
        if curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
            print_success "Elasticsearch is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "Elasticsearch failed to start within 5 minutes"
            exit 1
        fi
        sleep 10
        echo -n "."
    done
    
    # Wait for API
    print_status "Waiting for API server..."
    for i in {1..30}; do
        if curl -s http://localhost:8000/health >/dev/null 2>&1; then
            print_success "API server is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "API server failed to start within 5 minutes"
            exit 1
        fi
        sleep 10
        echo -n "."
    done
    
    # Wait for Kibana
    print_status "Waiting for Kibana..."
    for i in {1..30}; do
        if curl -s http://localhost:5601/api/status >/dev/null 2>&1; then
            print_success "Kibana is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            print_warning "Kibana may take longer to start, but other services are ready"
            break
        fi
        sleep 10
        echo -n "."
    done
}

# Test services
test_services() {
    print_status "Testing service endpoints..."
    
    # Test API health
    if response=$(curl -s http://localhost:8000/health); then
        print_success "✅ API Health Check: OK"
        echo "   Response: $response"
    else
        print_error "❌ API Health Check failed"
    fi
    
    # Test API endpoints
    if curl -s http://localhost:8000/api/v1/enums >/dev/null; then
        print_success "✅ API Enums endpoint: OK"
    else
        print_warning "⚠️  API Enums endpoint not ready"
    fi
    
    # Test Elasticsearch
    if response=$(curl -s http://localhost:9200/_cluster/health); then
        print_success "✅ Elasticsearch cluster: OK"
    else
        print_error "❌ Elasticsearch cluster check failed"
    fi
    
    # Test Redis (through API)
    if curl -s http://localhost:8000/api/v1/analytics/dashboard >/dev/null; then
        print_success "✅ Redis connection (via API): OK"
    else
        print_warning "⚠️  Redis connection may have issues"
    fi
}

# Display service URLs
show_services() {
    echo ""
    echo "🎉 Threat Intelligence Dashboard is ready!"
    echo ""
    echo "📍 Service URLs:"
    echo "   📖 API Documentation:  http://localhost:8000/docs"
    echo "   🔍 API Health Check:   http://localhost:8000/health"
    echo "   📊 Kibana Dashboard:   http://localhost:5601"
    echo "   🔎 Elasticsearch:      http://localhost:9200"
    echo ""
    echo "🧪 Quick API Tests:"
    echo "   curl http://localhost:8000/health"
    echo "   curl http://localhost:8000/api/v1/analytics/dashboard"
    echo "   curl http://localhost:8000/api/v1/enums"
    echo ""
    echo "📚 Documentation:"
    echo "   - Frontend Integration: docs/FRONTEND_API_GUIDE.md"
    echo "   - Deployment Guide:     docs/DEPLOYMENT_GUIDE.md"
    echo ""
    echo "🛑 To stop all services: docker-compose down"
    echo "📋 To view logs:         docker-compose logs -f"
}

# Show status
show_status() {
    print_status "Current service status:"
    echo ""
    if command_exists docker-compose; then
        docker-compose ps
    else
        docker compose ps
    fi
}

# Stop services
stop_services() {
    print_status "Stopping all services..."
    if command_exists docker-compose; then
        docker-compose down
    else
        docker compose down
    fi
    print_success "All services stopped"
}

# Show logs
show_logs() {
    if command_exists docker-compose; then
        docker-compose logs -f
    else
        docker compose logs -f
    fi
}

# Main menu
show_menu() {
    echo "🔒 Threat Intelligence Dashboard - Management Script"
    echo ""
    echo "Available commands:"
    echo "  start     - Start all services (full setup)"
    echo "  stop      - Stop all services"
    echo "  restart   - Restart all services" 
    echo "  status    - Show service status"
    echo "  logs      - Show service logs"
    echo "  test      - Test service endpoints"
    echo "  urls      - Show service URLs"
    echo "  help      - Show this help"
    echo ""
}

# Main script logic
main() {
    case "${1:-}" in
        "start")
            check_prerequisites
            setup_environment
            start_services
            wait_for_services
            test_services
            show_services
            ;;
        "stop")
            stop_services
            ;;
        "restart")
            stop_services
            sleep 2
            start_services
            wait_for_services
            test_services
            show_services
            ;;
        "status")
            show_status
            ;;
        "logs")
            show_logs
            ;;
        "test")
            test_services
            ;;
        "urls")
            show_services
            ;;
        "help"|"-h"|"--help")
            show_menu
            ;;
        "")
            show_menu
            echo ""
            print_status "No command specified. Use './run.sh start' to begin."
            ;;
        *)
            print_error "Unknown command: $1"
            show_menu
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"