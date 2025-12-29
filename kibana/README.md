# Kibana Dashboard Setup Guide

This guide explains how to set up Kibana dashboards for the Mini SIEM project.

## Prerequisites

- Elasticsearch running with indexed logs (run `log_parser.py` first)
- Kibana accessible at http://localhost:5601

## Step-by-Step Setup

### 1. Create Index Patterns

1. Open Kibana: http://localhost:5601
2. Navigate to **Stack Management** > **Index Patterns**
3. Click **Create index pattern**
4. For logs:
   - Index pattern name: `siem-logs-*`
   - Select `@timestamp` as the Time field
   - Click **Create index pattern**
5. For alerts:
   - Click **Create index pattern** again
   - Index pattern name: `siem-alerts`
   - Select `@timestamp` as the Time field
   - Click **Create index pattern**

### 2. Explore Data in Discover

1. Navigate to **Discover**
2. Select the `siem-logs-*` index pattern
3. Explore the logs and verify data is being indexed
4. Switch to `siem-alerts` index pattern to view alerts

### 3. Create Visualizations

#### Failed vs Successful Logins (Pie Chart)

1. Go to **Visualize Library**
2. Click **Create visualization**
3. Select **Pie**
4. Choose `siem-logs-*` index pattern
5. Configuration:
   - Slice by: Terms
   - Field: `success.keyword`
   - Size: 10
6. Save as "Failed vs Successful Logins"

#### Top Attacking IPs (Bar Chart)

1. Create new visualization
2. Select **Vertical Bar**
3. Choose `siem-logs-*` index pattern
4. Configuration:
   - X-axis: Terms, Field: `source_ip.keyword`, Size: 10, Order by: Count, Desc
   - Y-axis: Count
5. Save as "Top Attacking IPs"

#### Alerts by Severity (Pie Chart)

1. Create new visualization
2. Select **Pie**
3. Choose `siem-alerts` index pattern
4. Configuration:
   - Slice by: Terms
   - Field: `severity.keyword`
5. Save as "Alerts by Severity"

#### Events Timeline (Line Chart)

1. Create new visualization
2. Select **Line**
3. Choose `siem-logs-*` index pattern
4. Configuration:
   - X-axis: Date Histogram, Field: `@timestamp`, Interval: Auto
   - Y-axis: Count
5. Save as "Events Timeline"

#### Alert Types (Bar Chart)

1. Create new visualization
2. Select **Vertical Bar**
3. Choose `siem-alerts` index pattern
4. Configuration:
   - X-axis: Terms, Field: `alert_type.keyword`, Size: 10
   - Y-axis: Count
5. Save as "Alert Types"

#### MITRE ATT&CK Techniques (Data Table)

1. Create new visualization
2. Select **Data Table**
3. Choose `siem-alerts` index pattern
4. Configuration:
   - Rows: Terms, Field: `mitre_technique.keyword`
   - Add sub-bucket: Terms, Field: `mitre_tactic.keyword`
   - Metrics: Count
5. Save as "MITRE ATT&CK Techniques"

### 4. Create Dashboard

1. Navigate to **Dashboard**
2. Click **Create dashboard**
3. Click **Add** to add visualizations
4. Add all created visualizations:
   - Failed vs Successful Logins
   - Top Attacking IPs
   - Alerts by Severity
   - Events Timeline
   - Alert Types
   - MITRE ATT&CK Techniques
5. Arrange and resize visualizations as needed
6. Save dashboard as "Mini SIEM - SOC Dashboard"
7. Set auto-refresh interval (e.g., 30 seconds)

## Dashboard Layout Suggestions

```
┌─────────────────────────┬─────────────────────────┐
│ Failed vs Successful    │ Alerts by Severity      │
│ Logins (Pie)            │ (Pie)                   │
├─────────────────────────┼─────────────────────────┤
│ Events Timeline (Line)  │                         │
│                         │                         │
├─────────────────────────┼─────────────────────────┤
│ Top Attacking IPs (Bar) │ Alert Types (Bar)       │
├─────────────────────────┴─────────────────────────┤
│ MITRE ATT&CK Techniques (Table)                   │
└───────────────────────────────────────────────────┘
```

## Tips

- Use filters to focus on specific time ranges or events
- Create alerts/rules in Kibana for automatic notifications
- Export dashboards via Saved Objects for backup
- Use Discover for detailed log analysis with KQL (Kibana Query Language)

## Saved Objects API

You can also import/export dashboards programmatically:

```bash
# Export
curl -X GET "http://localhost:5601/api/saved_objects/_export" \
  -H "kbn-xsrf: true" \
  -d '{"objects":[{"type":"dashboard","id":"your-dashboard-id"}]}'

# Import
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -F file=@dashboard_export.ndjson
```

