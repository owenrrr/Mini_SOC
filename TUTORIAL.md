## 1. ES/Kibana Setup
https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-compose?utm_source=chatgpt.com


## Restart from the beginning

```bash
# Clean all existing docker containers
docker compose down -v --remove-orphans
# Clean existing zeek log folders
rm -rf zeek/logs/*.log
# Generate certs
docker compose -f docker-compose.yml -f docker-compose-setup.yml run --rm setup
# Run ES
docker compose -f docker-compose.yml up -d es01 es02 es03
# set kibana password
docker compose -f docker-compose.yml -f docker-compose-setup.yml run --rm setup-passwords
# Run kibana
docker compose -f docker-compose.yml up -d kibana
# Run Zeek to generate zeek logs
docker run --rm \
  -v "$(pwd)/zeek/pcap:/pcap" \
  -v "$(pwd)/zeek/logs:/logs" \
  -w /logs \
  zeek/zeek \
  zeek -C -r /pcap/sample.pcap \
  -e '@load policy/tuning/json-logs'
# Run filebeat
docker compose -f docker-compose.yml up -d --force-recreate filebeat

# Check data inside the filebeat container
docker exec -it docker-filebeat-1 sh -lc 'ls -lh /var/log/zeek'
docker exec -it docker-filebeat-1 sh -lc 'wc -l /var/log/zeek/conn.log'
docker exec -it docker-filebeat-1 sh -lc 'head -n 1 /var/log/zeek/conn.log'

# Check the data flows to ES successfully
# Open kibana and go Stack Management > Data Views > find if there's any index
```

# Create Visualization in kibana
- Record of Counts (Metric)

  Primary Metric: Count

  Breakdown: log.file.path

- Connections over time（Line）

  Horizontal axis: @timestamp (date histogram)

  Metric: Count

- Top source IPs（bar）

  X axis: Top values of id.orig_h.keyword

  Metric: Count

- Top destination IPs（bar）

  X axis: Top values of id.resp_h.keyword

  Metric: Count

- Destination ports distribution（bar）

  X axis: Top values of id.resp_p

  Metric: Count

- Protocol split（pie）

  Slice by: proto.keyword

  Metric: Count

- Connection states（bar）

  X axis: Top values of conn_state.keyword

  Metric: Count