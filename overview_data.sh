#!/bin/bash

# 📊 Comprehensive Data Overview Script
# Shows complete overview of threat intelligence data

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

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

print_data() {
    echo -e "${CYAN}📊 $1${NC}"
}

# Function to format JSON output
format_json() {
    if command -v jq > /dev/null 2>&1; then
        jq '.'
    elif python3 -c "import json" 2>/dev/null; then
        python3 -m json.tool
    else
        cat
    fi
}

# Get data counts
get_data_overview() {
    print_header "📈 Data Overview Summary"
    
    # Check services first
    if ! curl -s http://localhost:9200/_cluster/health > /dev/null; then
        print_warning "Elasticsearch is not accessible"
        return 1
    fi
    
    if ! curl -s http://localhost:8000/health > /dev/null; then
        print_warning "API is not accessible"
        return 1
    fi
    
    print_success "All services are running"
    echo ""
    
    # Get IOC count
    local ioc_total=$(curl -s "http://localhost:8000/api/v1/iocs?size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    print_data "Total IOCs: $ioc_total"
    
    # Get Threat Actor count  
    local actor_total=$(curl -s "http://localhost:8000/api/v1/threat-actors?size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    print_data "Total Threat Actors: $actor_total"
    
    # Get Alert count
    local alert_total=$(curl -s "http://localhost:8000/api/v1/alerts?size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    print_data "Total Alerts: $alert_total"
    
    local grand_total=$((ioc_total + actor_total + alert_total))
    echo ""
    print_success "Grand Total: $grand_total records"
    
    return 0
}

# Show IOC breakdown
show_ioc_breakdown() {
    print_header "🔍 IOC Detailed Breakdown"
    
    # Show sample IOCs by type
    echo -e "${BOLD}Sample IOCs by Type:${NC}"
    
    # IPs
    local ip_count=$(curl -s "http://localhost:8000/api/v1/iocs?type=ip&size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    print_data "IP Addresses: $ip_count"
    if [ "$ip_count" -gt 0 ]; then
        curl -s "http://localhost:8000/api/v1/iocs?type=ip&size=3" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('data', []):
    print(f\"  📍 {item['value']} ({item['threat_level']}) - {item['description'][:50]}...\")
" 2>/dev/null || true
    fi
    echo ""
    
    # Domains
    local domain_count=$(curl -s "http://localhost:8000/api/v1/iocs?type=domain&size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    print_data "Domains: $domain_count"
    if [ "$domain_count" -gt 0 ]; then
        curl -s "http://localhost:8000/api/v1/iocs?type=domain&size=3" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('data', []):
    print(f\"  🌐 {item['value']} ({item['threat_level']}) - {item['description'][:50]}...\")
" 2>/dev/null || true
    fi
    echo ""
    
    # File Hashes
    local hash_count=$(curl -s "http://localhost:8000/api/v1/iocs?type=file_hash&size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    print_data "File Hashes: $hash_count"
    if [ "$hash_count" -gt 0 ]; then
        curl -s "http://localhost:8000/api/v1/iocs?type=file_hash&size=3" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('data', []):
    print(f\"  🔒 {item['value'][:32]}... ({item['threat_level']}) - {item['description'][:40]}...\")
" 2>/dev/null || true
    fi
    echo ""
    
    # Threat Level Distribution
    print_data "Threat Level Distribution:"
    for level in critical high medium low; do
        local level_count=$(curl -s "http://localhost:8000/api/v1/iocs?threat_level=$level&size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
        printf "  %-10s: %s\n" "$level" "$level_count"
    done
}

# Show threat actors
show_threat_actors() {
    print_header "👤 Threat Actor Overview"
    
    local actor_total=$(curl -s "http://localhost:8000/api/v1/threat-actors?size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    
    if [ "$actor_total" -eq 0 ]; then
        print_warning "No threat actors found"
        print_info "Run additional seeding to create threat actor data"
        return 0
    fi
    
    print_data "Found $actor_total threat actors:"
    
    curl -s "http://localhost:8000/api/v1/threat-actors?size=10" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('data', []):
    print(f\"  🎭 {item['name']} ({item['actor_type']}) - {item['country']}\")
    print(f\"     {item['description'][:80]}...\")
    print()
" 2>/dev/null || true
}

# Show alerts
show_alerts() {
    print_header "🚨 Alert Overview"
    
    local alert_total=$(curl -s "http://localhost:8000/api/v1/alerts?size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    
    if [ "$alert_total" -eq 0 ]; then
        print_warning "No alerts found"
        print_info "Run additional seeding to create alert data"
        return 0
    fi
    
    print_data "Found $alert_total alerts:"
    
    # Alert severity distribution
    print_data "Alert Severity Distribution:"
    for severity in critical high medium low; do
        local sev_count=$(curl -s "http://localhost:8000/api/v1/alerts?severity=$severity&size=1" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
        printf "  %-10s: %s\n" "$severity" "$sev_count"
    done
    echo ""
    
    # Recent alerts
    print_data "Recent Alerts:"
    curl -s "http://localhost:8000/api/v1/alerts?size=5" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('data', []):
    print(f\"  🚨 {item['title']} ({item['severity']}) - {item['status']}\")
    print(f\"     {item['description'][:60]}...\")
    print()
" 2>/dev/null || true
}

# Show API endpoints
show_api_endpoints() {
    print_header "🔌 Available API Endpoints"
    
    echo "📋 Main Endpoints:"
    echo "   • GET  /api/v1/iocs                - List all IOCs"
    echo "   • GET  /api/v1/iocs?type=ip        - Filter IOCs by type"
    echo "   • GET  /api/v1/iocs?threat_level=critical - Filter by threat level"
    echo "   • GET  /api/v1/threat-actors       - List threat actors"
    echo "   • GET  /api/v1/alerts             - List alerts"
    echo "   • GET  /api/v1/analytics/dashboard - Analytics data"
    echo "   • GET  /health                    - Health check"
    echo ""
    echo "📖 Documentation:"
    echo "   • Interactive API Docs: http://localhost:8000/docs"
    echo "   • OpenAPI Schema: http://localhost:8000/openapi.json"
}

# Show sample queries
show_sample_queries() {
    print_header "📝 Sample Test Queries"
    
    echo "🔍 Direct Elasticsearch Queries:"
    echo "   curl 'http://localhost:9200/threat_iocs/_search?q=threat_level:critical&size=5'"
    echo "   curl 'http://localhost:9200/threat_iocs/_search?q=tags:phishing'"
    echo "   curl 'http://localhost:9200/threat_iocs/_count'"
    echo ""
    echo "🌐 API Queries:"
    echo "   curl 'http://localhost:8000/api/v1/iocs?size=5'"
    echo "   curl 'http://localhost:8000/api/v1/iocs?type=domain'"
    echo "   curl 'http://localhost:8000/api/v1/iocs?threat_level=critical'"
    echo "   curl 'http://localhost:8000/api/v1/analytics/dashboard'"
    echo ""
    echo "📊 Test in Browser:"
    echo "   • Kibana: http://localhost:5601"
    echo "   • API Docs: http://localhost:8000/docs"
}

# Show seeding options
show_seeding_options() {
    print_header "🌱 Data Seeding Options"
    
    echo "Available seeding scripts:"
    echo "   • ./seed_docker.sh           - Seed data using Docker (recommended)"
    echo "   • ./seed_data.sh             - Seed data with local Python environment"
    echo "   • ./check_data.py            - Check existing data"
    echo ""
    echo "Sample commands:"
    echo "   ./seed_docker.sh             # Full seeding using Docker"
    echo "   python3 check_data.py        # Quick data check"
    echo ""
    echo "If you need more data:"
    echo "   - Modify the scripts to add more IOCs, actors, or alerts"
    echo "   - Use the API to add data programmatically"
    echo "   - Import data from external threat intelligence feeds"
}

# Main execution
main() {
    print_header "🔍 Threat Intelligence Dashboard - Data Overview"
    echo -e "${BLUE}Generated at: $(date)${NC}"
    echo ""
    
    # Get overview
    if ! get_data_overview; then
        print_warning "Unable to get complete data overview"
        echo ""
        print_info "Make sure services are running:"
        print_info "  docker-compose up -d"
        exit 1
    fi
    
    # Show detailed breakdowns
    show_ioc_breakdown
    show_threat_actors  
    show_alerts
    show_api_endpoints
    show_sample_queries
    show_seeding_options
    
    print_header "🎉 Data Overview Complete!"
    print_success "Your threat intelligence dashboard is operational and ready for testing!"
    
    echo ""
    print_info "Quick Links:"
    print_info "  • Kibana Dashboard: http://localhost:5601"
    print_info "  • API Documentation: http://localhost:8000/docs"
    print_info "  • Health Check: http://localhost:8000/health"
}

# Parse command line arguments
case "${1:-}" in
    --iocs)
        show_ioc_breakdown
        ;;
    --actors)
        show_threat_actors
        ;;
    --alerts)
        show_alerts
        ;;
    --api)
        show_api_endpoints
        ;;
    --queries)
        show_sample_queries
        ;;
    --seed)
        show_seeding_options
        ;;
    --help)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --iocs      Show IOC breakdown only"
        echo "  --actors    Show threat actors only"
        echo "  --alerts    Show alerts only"
        echo "  --api       Show API endpoints only"
        echo "  --queries   Show sample queries only"
        echo "  --seed      Show seeding options only"
        echo "  --help      Show this help"
        echo ""
        echo "Run without options for complete overview"
        ;;
    *)
        main
        ;;
esac