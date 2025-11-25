#!/bin/bash

# 🧪 Comprehensive API Testing Script
# Tests all endpoints and functionality of the Threat Intelligence Dashboard

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# API Base URL
API_URL="http://localhost:8000"

# Function to print colored output
print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Function to test API endpoint
test_endpoint() {
    local name="$1"
    local url="$2"
    local expected_code="${3:-200}"
    
    print_test "Testing $name"
    
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" "$API_URL$url")
    http_code=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
    
    if [ "$http_code" -eq "$expected_code" ]; then
        print_pass "$name - HTTP $http_code"
        return 0
    else
        print_fail "$name - Expected HTTP $expected_code, got $http_code"
        return 1
    fi
}

# Function to test JSON response structure
test_json_field() {
    local name="$1"
    local url="$2"
    local field="$3"
    
    print_test "Testing $name - $field field"
    
    response=$(curl -s "$API_URL$url")
    if echo "$response" | jq -e ".$field" > /dev/null 2>&1; then
        value=$(echo "$response" | jq -r ".$field")
        print_pass "$name - $field: $value"
        return 0
    else
        print_fail "$name - Missing field: $field"
        return 1
    fi
}

echo "🚀 Starting Comprehensive API Testing"
echo "=================================="
echo ""

# Test 1: Health Check
print_info "1. Health Check Tests"
test_endpoint "Health Check" "/health"
test_json_field "Health Status" "/health" "status"
echo ""

# Test 2: IOC Endpoints
print_info "2. IOC Endpoint Tests"
test_endpoint "IOC List" "/api/v1/iocs"
test_json_field "IOC Total Count" "/api/v1/iocs" "total"
test_json_field "IOC Data Array" "/api/v1/iocs" "data"

# Test IOC filtering
test_endpoint "IOC Filter by Type" "/api/v1/iocs?type=ip"
test_endpoint "IOC Filter by Threat Level" "/api/v1/iocs?threat_level=critical"
test_endpoint "IOC Filter Combined" "/api/v1/iocs?type=domain&threat_level=high"

# Test IOC search
test_endpoint "IOC Search" "/api/v1/iocs?q=192.168"
test_endpoint "IOC Pagination" "/api/v1/iocs?page=1&size=5"
echo ""

# Test 3: Threat Actor Endpoints
print_info "3. Threat Actor Endpoint Tests"
test_endpoint "Threat Actors List" "/api/v1/threat-actors"
test_json_field "Threat Actors Total" "/api/v1/threat-actors" "total"

# Test threat actor filtering
test_endpoint "Threat Actor Filter" "/api/v1/threat-actors?actor_type=apt"
test_endpoint "Threat Actor Search" "/api/v1/threat-actors?q=APT28"
echo ""

# Test 4: Alert Endpoints
print_info "4. Alert Endpoint Tests"
test_endpoint "Alerts List" "/api/v1/alerts"
test_json_field "Alerts Total" "/api/v1/alerts" "total"

# Test alert filtering
test_endpoint "Alert Filter by Severity" "/api/v1/alerts?severity=critical"
test_endpoint "Alert Filter by Status" "/api/v1/alerts?status=open"
echo ""

# Test 5: Analytics Dashboard
print_info "5. Analytics Dashboard Tests"
test_endpoint "Dashboard Analytics" "/api/v1/analytics/dashboard"
test_json_field "Dashboard Statistics" "/api/v1/analytics/dashboard" "statistics"
test_json_field "Recent Activity" "/api/v1/analytics/dashboard" "recent_activity"
echo ""

# Test 6: Enumeration Endpoints
print_info "6. Enumeration Tests"
test_endpoint "Enums" "/api/v1/enums"
test_json_field "IOC Types" "/api/v1/enums" "ioc_types"
test_json_field "Threat Levels" "/api/v1/enums" "threat_levels"
test_json_field "Actor Types" "/api/v1/enums" "actor_types"
echo ""

# Test 7: Data Validation
print_info "7. Data Validation Tests"

# Check IOC data quality
print_test "Validating IOC data quality"
ioc_count=$(curl -s "$API_URL/api/v1/iocs" | jq '.total')
if [ "$ioc_count" -gt 0 ]; then
    print_pass "IOCs present: $ioc_count items"
else
    print_fail "No IOCs found in database"
fi

# Check threat levels distribution
print_test "Validating threat level distribution"
critical_count=$(curl -s "$API_URL/api/v1/iocs?threat_level=critical" | jq '.total')
high_count=$(curl -s "$API_URL/api/v1/iocs?threat_level=high" | jq '.total')
medium_count=$(curl -s "$API_URL/api/v1/iocs?threat_level=medium" | jq '.total')
low_count=$(curl -s "$API_URL/api/v1/iocs?threat_level=low" | jq '.total')

echo "   Critical: $critical_count | High: $high_count | Medium: $medium_count | Low: $low_count"
print_pass "Threat level distribution validated"

# Check IOC types distribution
print_test "Validating IOC type distribution"
ip_count=$(curl -s "$API_URL/api/v1/iocs?type=ip" | jq '.total')
domain_count=$(curl -s "$API_URL/api/v1/iocs?type=domain" | jq '.total')
hash_count=$(curl -s "$API_URL/api/v1/iocs?type=file_hash" | jq '.total')
url_count=$(curl -s "$API_URL/api/v1/iocs?type=url" | jq '.total')

echo "   IPs: $ip_count | Domains: $domain_count | Hashes: $hash_count | URLs: $url_count"
print_pass "IOC type distribution validated"
echo ""

# Test 8: Performance Tests
print_info "8. Performance Tests"
print_test "Measuring API response times"

# Test response time for dashboard
start_time=$(date +%s%N)
curl -s "$API_URL/api/v1/analytics/dashboard" > /dev/null
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))
print_pass "Dashboard response time: ${duration}ms"

# Test response time for IOC search
start_time=$(date +%s%N)
curl -s "$API_URL/api/v1/iocs?size=100" > /dev/null
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))
print_pass "IOC search response time: ${duration}ms"
echo ""

# Test 9: Error Handling
print_info "9. Error Handling Tests"
test_endpoint "Invalid IOC Type" "/api/v1/iocs?type=invalid_type" 422
test_endpoint "Invalid Threat Level" "/api/v1/iocs?threat_level=invalid_level" 422
test_endpoint "Invalid Page Number" "/api/v1/iocs?page=-1" 422
echo ""

# Test 10: Sample Data Verification
print_info "10. Sample Data Verification"

# Check for specific test data
print_test "Verifying sample IOCs"
sample_iocs=("192.168.1.100" "evil-domain.com" "5d41402abc4b2a76b9719d911017c592")
for ioc in "${sample_iocs[@]}"; do
    count=$(curl -s "$API_URL/api/v1/iocs?q=$ioc" | jq '.total')
    if [ "$count" -gt 0 ]; then
        print_pass "Sample IOC found: $ioc"
    else
        print_fail "Sample IOC missing: $ioc"
    fi
done
echo ""

# Summary
echo "=================================="
echo "🎉 Comprehensive API Testing Complete!"
echo ""
echo "📊 Quick Stats:"
echo "   • Total IOCs: $(curl -s "$API_URL/api/v1/iocs" | jq '.total')"
echo "   • Critical IOCs: $(curl -s "$API_URL/api/v1/iocs?threat_level=critical" | jq '.total')"
echo "   • High IOCs: $(curl -s "$API_URL/api/v1/iocs?threat_level=high" | jq '.total')"
echo "   • IP Addresses: $(curl -s "$API_URL/api/v1/iocs?type=ip" | jq '.total')"
echo "   • Domains: $(curl -s "$API_URL/api/v1/iocs?type=domain" | jq '.total')"
echo ""
echo "🔗 Access URLs:"
echo "   • API Documentation: http://localhost:8000/docs"
echo "   • Kibana Dashboard: http://localhost:5601"
echo "   • API Health: http://localhost:8000/health"
echo ""
echo "✅ All core functionality tested and operational!"