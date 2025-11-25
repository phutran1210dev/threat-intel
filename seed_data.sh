#!/bin/bash

# 🌱 Threat Intelligence Dashboard - Data Seeding Script
# Comprehensive script to seed all test data for the dashboard

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BOLD}${BLUE}============================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to check if services are running
check_services() {
    print_info "Checking required services..."
    
    # Check Elasticsearch
    if curl -s http://localhost:9200/_cluster/health > /dev/null; then
        print_success "Elasticsearch is running"
    else
        print_error "Elasticsearch is not accessible at http://localhost:9200"
        print_info "Please start Elasticsearch first:"
        print_info "  docker-compose up -d elasticsearch"
        return 1
    fi
    
    # Check if Kibana is running (optional but recommended)
    if curl -s http://localhost:5601/api/status > /dev/null; then
        print_success "Kibana is running"
    else
        print_warning "Kibana is not running (optional for seeding)"
        print_info "To start Kibana: docker-compose up -d kibana"
    fi
    
    return 0
}

# Function to setup Python environment
setup_python_env() {
    print_info "Setting up Python environment..."
    
    # Check if we're in a virtual environment or have the required packages
    if python3 -c "import elasticsearch_dsl, elasticsearch" 2>/dev/null; then
        print_success "Required Python packages are available"
        return 0
    fi
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        print_info "Creating Python virtual environment..."
        python3 -m venv venv
        print_success "Virtual environment created"
    fi
    
    # Activate virtual environment
    print_info "Activating virtual environment..."
    source venv/bin/activate
    
    # Install requirements
    print_info "Installing Python dependencies..."
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    print_success "Dependencies installed"
    
    return 0
}

# Function to run data seeding
run_seeding() {
    print_header "🌱 Starting Data Seeding Process"
    
    # Run the Python seeding script
    print_info "Running comprehensive data seeding script..."
    
    if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    fi
    
    # Set environment variables for Docker containers
    export ELASTICSEARCH_URL="http://localhost:9200"
    export PYTHONPATH="${PWD}:${PYTHONPATH}"
    
    # Run the seeding script
    python3 seed_all_data.py
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        print_success "Data seeding completed successfully!"
        return 0
    else
        print_error "Data seeding failed with exit code: $exit_code"
        return $exit_code
    fi
}

# Function to verify seeded data
verify_data() {
    print_header "🔍 Verifying Seeded Data"
    
    # Check IOC count
    local ioc_count=$(curl -s "http://localhost:9200/threat_iocs/_count" | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
    print_info "IOCs in database: $ioc_count"
    
    # Check Threat Actor count
    local actor_count=$(curl -s "http://localhost:9200/threat_actors/_count" | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
    print_info "Threat Actors in database: $actor_count"
    
    # Check Alert count
    local alert_count=$(curl -s "http://localhost:9200/threat_alerts/_count" | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
    print_info "Alerts in database: $alert_count"
    
    local total=$((ioc_count + actor_count + alert_count))
    
    if [ $total -gt 0 ]; then
        print_success "Total records in database: $total"
        return 0
    else
        print_error "No data found in database!"
        return 1
    fi
}

# Function to show usage information
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --check-only    Only check services and dependencies"
    echo "  --verify-only   Only verify existing data"
    echo "  --force         Force re-seeding (will not skip existing data)"
    echo "  --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run full seeding process"
    echo "  $0 --check-only      # Just check if services are ready"
    echo "  $0 --verify-only     # Just verify existing data"
    echo "  $0 --force           # Force complete re-seeding"
}

# Function to show dashboard access information
show_access_info() {
    print_header "🚀 Dashboard Access Information"
    
    print_info "Your threat intelligence dashboard is ready!"
    echo ""
    echo "📊 Access Points:"
    echo "   • Kibana Dashboard: http://localhost:5601"
    echo "   • API Documentation: http://localhost:8000/docs"
    echo "   • Elasticsearch: http://localhost:9200"
    echo ""
    echo "🔍 Sample Kibana Searches:"
    echo "   • All Critical IOCs: threat_level:critical"
    echo "   • APT Groups: actor_type:apt"
    echo "   • Recent Alerts: created_at:[now-7d TO now]"
    echo ""
    echo "🧪 Test the API:"
    echo "   curl http://localhost:8000/api/v1/iocs"
    echo "   curl http://localhost:8000/api/v1/threat-actors"
    echo "   curl http://localhost:8000/api/v1/alerts"
}

# Main execution
main() {
    print_header "🌱 Threat Intelligence Dashboard - Data Seeding"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --check-only)
                check_services
                exit $?
                ;;
            --verify-only)
                verify_data
                exit $?
                ;;
            --force)
                FORCE_SEED=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Step 1: Check services
    if ! check_services; then
        print_error "Service check failed. Please ensure services are running."
        exit 1
    fi
    
    # Step 2: Setup Python environment
    if ! setup_python_env; then
        print_error "Failed to setup Python environment"
        exit 1
    fi
    
    # Step 3: Run seeding
    if ! run_seeding; then
        print_error "Data seeding failed"
        exit 1
    fi
    
    # Step 4: Verify data
    if ! verify_data; then
        print_warning "Data verification had issues, but seeding may have partially succeeded"
    fi
    
    # Step 5: Show access information
    show_access_info
    
    print_header "🎉 Setup Complete!"
    print_success "Your threat intelligence dashboard is ready for testing!"
}

# Run main function with all arguments
main "$@"