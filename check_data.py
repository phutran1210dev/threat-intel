#!/usr/bin/env python3
"""
🔍 Quick Data Check Script
Quickly check what data exists in the threat intelligence database
"""

import sys
import os
import requests
import json
from datetime import datetime

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(title: str):
    """Print section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{title}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")

def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def print_info(message: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")

def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}❌ {message}{Colors.END}")

def check_elasticsearch():
    """Check Elasticsearch connectivity and health"""
    es_url = "http://localhost:9200"
    
    try:
        # Check cluster health
        response = requests.get(f"{es_url}/_cluster/health", timeout=5)
        if response.status_code == 200:
            health = response.json()
            print_success(f"Elasticsearch Status: {health['status']}")
            print_info(f"Cluster Name: {health['cluster_name']}")
            print_info(f"Number of Nodes: {health['number_of_nodes']}")
            return True
        else:
            print_error(f"Elasticsearch returned status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Cannot connect to Elasticsearch: {e}")
        return False

def check_indices():
    """Check available indices"""
    es_url = "http://localhost:9200"
    
    try:
        response = requests.get(f"{es_url}/_cat/indices?format=json", timeout=5)
        if response.status_code == 200:
            indices = response.json()
            threat_indices = [idx for idx in indices if 'threat' in idx['index']]
            
            if threat_indices:
                print_info("Available threat intelligence indices:")
                for idx in threat_indices:
                    print(f"  📊 {idx['index']}: {idx['docs.count']} documents ({idx['store.size']})")
            else:
                print_info("No threat intelligence indices found")
            
            return threat_indices
        else:
            print_error(f"Failed to get indices: {response.status_code}")
            return []
    except Exception as e:
        print_error(f"Error checking indices: {e}")
        return []

def check_data_counts():
    """Check document counts in each index"""
    es_url = "http://localhost:9200"
    indices = ['threat_iocs', 'threat_actors', 'threat_alerts']
    
    total_docs = 0
    
    for index in indices:
        try:
            response = requests.get(f"{es_url}/{index}/_count", timeout=5)
            if response.status_code == 200:
                count_data = response.json()
                count = count_data['count']
                total_docs += count
                print_info(f"{index}: {count} documents")
                
                # Get sample document if exists
                if count > 0:
                    sample_response = requests.get(f"{es_url}/{index}/_search?size=1", timeout=5)
                    if sample_response.status_code == 200:
                        sample_data = sample_response.json()
                        if sample_data['hits']['hits']:
                            sample_doc = sample_data['hits']['hits'][0]['_source']
                            if index == 'threat_iocs':
                                print(f"      Sample IOC: {sample_doc.get('value', 'N/A')} ({sample_doc.get('type', 'N/A')})")
                            elif index == 'threat_actors':
                                print(f"      Sample Actor: {sample_doc.get('name', 'N/A')} ({sample_doc.get('actor_type', 'N/A')})")
                            elif index == 'threat_alerts':
                                print(f"      Sample Alert: {sample_doc.get('title', 'N/A')} ({sample_doc.get('severity', 'N/A')})")
            else:
                print_info(f"{index}: Index not found or empty")
        except Exception as e:
            print_error(f"Error checking {index}: {e}")
    
    return total_docs

def check_ioc_breakdown():
    """Get detailed IOC breakdown by type"""
    es_url = "http://localhost:9200"
    
    try:
        # Aggregation query to get IOC types
        query = {
            "size": 0,
            "aggs": {
                "ioc_types": {
                    "terms": {
                        "field": "type.keyword",
                        "size": 20
                    }
                },
                "threat_levels": {
                    "terms": {
                        "field": "threat_level.keyword",
                        "size": 10
                    }
                }
            }
        }
        
        response = requests.post(f"{es_url}/threat_iocs/_search", 
                               json=query, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            # IOC Types breakdown
            if 'aggregations' in data:
                print_info("IOC Types breakdown:")
                for bucket in data['aggregations']['ioc_types']['buckets']:
                    print(f"      {bucket['key']}: {bucket['doc_count']}")
                
                print_info("Threat Levels breakdown:")
                for bucket in data['aggregations']['threat_levels']['buckets']:
                    print(f"      {bucket['key']}: {bucket['doc_count']}")
        
    except Exception as e:
        print_error(f"Error getting IOC breakdown: {e}")

def check_alert_status():
    """Check alert status distribution"""
    es_url = "http://localhost:9200"
    
    try:
        # Aggregation query for alert status
        query = {
            "size": 0,
            "aggs": {
                "alert_severity": {
                    "terms": {
                        "field": "severity.keyword",
                        "size": 10
                    }
                },
                "alert_status": {
                    "terms": {
                        "field": "status.keyword",
                        "size": 10
                    }
                }
            }
        }
        
        response = requests.post(f"{es_url}/threat_alerts/_search", 
                               json=query, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'aggregations' in data:
                print_info("Alert Severity breakdown:")
                for bucket in data['aggregations']['alert_severity']['buckets']:
                    print(f"      {bucket['key']}: {bucket['doc_count']}")
                
                print_info("Alert Status breakdown:")
                for bucket in data['aggregations']['alert_status']['buckets']:
                    print(f"      {bucket['key']}: {bucket['doc_count']}")
        
    except Exception as e:
        print_error(f"Error getting alert breakdown: {e}")

def check_api_status():
    """Check if API is running"""
    api_url = "http://localhost:8000"
    
    try:
        response = requests.get(f"{api_url}/health", timeout=5)
        if response.status_code == 200:
            print_success("API Server is running")
            print_info("API Docs: http://localhost:8000/docs")
        else:
            print_error(f"API returned status code: {response.status_code}")
    except Exception as e:
        print_error(f"API is not accessible: {e}")

def check_kibana_status():
    """Check if Kibana is running"""
    kibana_url = "http://localhost:5601"
    
    try:
        response = requests.get(f"{kibana_url}/api/status", timeout=5)
        if response.status_code == 200:
            print_success("Kibana is running")
            print_info("Kibana Dashboard: http://localhost:5601")
        else:
            print_error(f"Kibana returned status code: {response.status_code}")
    except Exception as e:
        print_error(f"Kibana is not accessible: {e}")

def main():
    """Main function"""
    print_header("🔍 Threat Intelligence Dashboard - Data Check")
    print_info(f"Checking data status at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check Elasticsearch
    print_header("📊 Elasticsearch Status")
    if not check_elasticsearch():
        print_error("Cannot proceed without Elasticsearch")
        return False
    
    # Check indices
    print_header("📋 Available Indices")
    indices = check_indices()
    
    # Check data counts
    print_header("📈 Data Summary")
    total_docs = check_data_counts()
    
    if total_docs > 0:
        print_success(f"Total documents in database: {total_docs}")
        
        # Detailed breakdowns
        print_header("📊 IOC Analysis")
        check_ioc_breakdown()
        
        print_header("🚨 Alert Analysis")  
        check_alert_status()
    else:
        print_error("No threat intelligence data found!")
        print_info("Run './seed_data.sh' to populate with test data")
    
    # Check services
    print_header("🚀 Service Status")
    check_api_status()
    check_kibana_status()
    
    print_header("✅ Data Check Complete")
    
    if total_docs == 0:
        print_info("To populate with test data, run:")
        print_info("  ./seed_data.sh")
    else:
        print_info("To access your dashboard:")
        print_info("  Kibana: http://localhost:5601")
        print_info("  API: http://localhost:8000/docs")

if __name__ == "__main__":
    main()