# Quick Setup Guide

## Prerequisites

- Python 3.8+
- Docker & Docker Compose (optional, recommended)
- pip (Python package manager)

## Installation Steps

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start Elasticsearch and Kibana

**Option A: Using Docker Compose (Recommended)**

```bash
docker-compose up -d
```

Wait for services to be ready (about 1-2 minutes), then verify:

```bash
# Check Elasticsearch
curl http://localhost:9200

# Check Kibana (open in browser)
# http://localhost:5601
```

**Option B: Manual Installation**

Install and run Elasticsearch and Kibana separately. See official documentation.

### 3. Generate Sample Logs (Optional)

```bash
python simulators/brute_force_sim.py
python simulators/port_scan_sim.py
python simulators/failed_login_sim.py
```

### 4. Parse and Index Logs

```bash
python scripts/log_parser.py --input logs/ --output es
```

Or use the all-in-one script:

```bash
python run_all.py
```

### 5. Run Detection Engine

```bash
python scripts/event_detector.py
```

### 6. Start Flask Dashboard

```bash
cd webapp
python app.py
```

Access at: http://localhost:5000

### 7. Set Up Kibana Dashboard

Follow instructions in `kibana/README.md` to create visualizations and dashboards.

## Verification

1. **Check Elasticsearch indices:**
   ```bash
   curl http://localhost:9200/_cat/indices?v
   ```
   You should see `siem-logs` and `siem-alerts` indices.

2. **Check logs in Kibana:**
   - Open http://localhost:5601
   - Go to Discover
   - Create index pattern: `siem-logs-*`

3. **Check alerts in Flask dashboard:**
   - Open http://localhost:5000
   - View alerts and statistics

## Troubleshooting

### Elasticsearch Connection Error

- Verify Elasticsearch is running: `curl http://localhost:9200`
- Check configuration in `config/config.yaml`
- Ensure ports 9200 and 5601 are not blocked

### Import Errors

- Ensure you're running scripts from project root directory
- Install all dependencies: `pip install -r requirements.txt`
- Check Python version: `python --version` (should be 3.8+)

### No Data in Kibana

- Verify logs are indexed: `python scripts/log_parser.py --input logs/ --output es`
- Check index pattern matches: `siem-logs-*`
- Refresh Kibana discover view

### Detection Rules Not Triggering

- Ensure logs are indexed in Elasticsearch
- Check detection thresholds in `config/detection_config.yaml`
- Run detection: `python scripts/event_detector.py`

