# 🌱 Threat Intelligence Dashboard - Data Seeding Scripts

Các script được tạo để seed và kiểm tra dữ liệu cho hệ thống Threat Intelligence Dashboard.

## 📋 Danh Sách Scripts

### 1. 🐳 **seed_docker.sh** (Khuyên dùng)
- **Mục đích**: Seed data sử dụng Docker container
- **Ưu điểm**: Không cần cài đặt Python dependencies trên host
- **Cách dùng**: `./seed_docker.sh`
- **Tạo**: 16 IOCs đa dạng (IPs, domains, hashes, URLs, emails)

### 2. 🐍 **seed_all_data.py**
- **Mục đích**: Script Python chi tiết với đầy đủ tính năng
- **Tạo**: IOCs, Threat Actors, Alerts với data phong phú
- **Cần**: Python environment với dependencies
- **Cách dùng**: `python3 seed_all_data.py`

### 3. 🔧 **seed_data.sh**
- **Mục đích**: Wrapper script cho Python seeding
- **Tính năng**: Tự động setup virtual environment
- **Cách dùng**: `./seed_data.sh`
- **Options**: `--check-only`, `--verify-only`, `--force`

### 4. 🔍 **check_data.py**
- **Mục đích**: Kiểm tra nhanh data hiện có
- **Tính năng**: Hiển thị thống kê chi tiết
- **Cách dùng**: `python3 check_data.py`

### 5. 📊 **overview_data.sh** (Script tổng quan)
- **Mục đích**: Hiển thị overview toàn diện về data
- **Tính năng**: 
  - Thống kê tổng quan
  - Phân tích IOCs theo type và threat level
  - Hiển thị threat actors và alerts
  - Danh sách API endpoints
  - Sample queries và commands
- **Cách dùng**: `./overview_data.sh`
- **Options**: `--iocs`, `--actors`, `--alerts`, `--api`, `--queries`, `--seed`

## 🚀 Cách Sử Dụng

### Bước 1: Khởi động services
```bash
docker-compose up -d
```

### Bước 2: Seed data (chọn một trong các cách)
```bash
# Cách 1: Sử dụng Docker (khuyên dùng)
./seed_docker.sh

# Cách 2: Sử dụng Python local
./seed_data.sh

# Cách 3: Chỉ Python script
python3 seed_all_data.py
```

### Bước 3: Kiểm tra data
```bash
# Overview tổng quan
./overview_data.sh

# Kiểm tra nhanh
python3 check_data.py

# Chỉ xem IOCs
./overview_data.sh --iocs
```

## 📈 Dữ Liệu Được Tạo

### IOCs (Indicators of Compromise)
- **16 IOCs** đa dạng:
  - 6 IP addresses (Tor exits, C2 servers, scanners)
  - 4 Domains (phishing, malware distribution)
  - 4 File hashes (ransomware, trojans, backdoors)
  - 2 URLs (exploit kits, phishing pages)
  - Email addresses (phishing campaigns)

### Threat Actors (Planned)
- APT28 (Fancy Bear) - Russian military intelligence
- Lazarus Group - North Korean state-sponsored
- FIN7 - Financially motivated cybercriminals
- Conti Ransomware Group - RaaS operation
- DarkHalo (UNC2452) - SolarWinds hackers

### Alerts (Planned)
- Phishing campaign detections
- APT infrastructure activity
- Malware C2 communications
- Data exfiltration attempts
- Ransomware detections

## 🔍 Sample Queries

### API Queries
```bash
# Tất cả IOCs
curl "http://localhost:8000/api/v1/iocs"

# IOCs critical
curl "http://localhost:8000/api/v1/iocs?threat_level=critical"

# Chỉ IP addresses
curl "http://localhost:8000/api/v1/iocs?type=ip"

# Dashboard analytics
curl "http://localhost:8000/api/v1/analytics/dashboard"
```

### Elasticsearch Direct
```bash
# Count IOCs
curl "http://localhost:9200/threat_iocs/_count"

# Search phishing IOCs
curl "http://localhost:9200/threat_iocs/_search?q=tags:phishing"

# Critical threat level
curl "http://localhost:9200/threat_iocs/_search?q=threat_level:critical"
```

## 🌐 Access Points

- **Kibana Dashboard**: http://localhost:5601
- **API Documentation**: http://localhost:8000/docs
- **API Health Check**: http://localhost:8000/health
- **Elasticsearch**: http://localhost:9200

## 🛠️ Troubleshooting

### Services không chạy
```bash
# Kiểm tra containers
docker ps

# Khởi động lại
docker-compose down && docker-compose up -d

# Xem logs
docker-compose logs elasticsearch
```

### Python dependencies missing
```bash
# Sử dụng Docker thay thế
./seed_docker.sh

# Hoặc cài đặt local
pip install -r requirements.txt
```

### Data không được tạo
```bash
# Kiểm tra Elasticsearch health
curl http://localhost:9200/_cluster/health

# Xem index mappings
curl http://localhost:9200/threat_iocs/_mapping
```

## 📝 Customization

### Thêm IOCs mới
Chỉnh sửa `seed_docker.sh` hoặc `seed_all_data.py` và thêm vào array `iocs`:

```python
{
    'value': 'your-malicious-domain.com',
    'type': 'domain',
    'threat_level': 'high',
    'source': 'custom',
    'tags': ['custom-tag'],
    'confidence': 90,
    'description': 'Your custom IOC description'
}
```

### Thêm Threat Actors mới
```python
{
    'name': 'Custom APT Group',
    'actor_type': 'apt',
    'aliases': ['Custom Group'],
    'description': 'Custom threat actor description',
    'country': 'Unknown',
    'motivation': ['espionage'],
    'sophistication': 'high',
    'targets': ['government'],
    'ttps': ['custom-technique'],
    'tools': ['Custom Tool']
}
```

## ✅ Status

- ✅ IOC seeding: Hoạt động (16 IOCs created)
- ⚠️ Threat Actor seeding: Cần fix schema conflicts
- ⚠️ Alert seeding: Cần fix schema conflicts
- ✅ API endpoints: Hoạt động tốt
- ✅ Elasticsearch: Hoạt động tốt
- ✅ Kibana: Sẵn sàng cho visualization

## 🎯 Kế Hoạch Tiếp Theo

1. Fix schema conflicts cho Threat Actors và Alerts
2. Tạo thêm diverse IOCs
3. Implement automated threat intelligence feeds
4. Tạo Kibana dashboards tự động
5. Thêm data validation và cleanup scripts