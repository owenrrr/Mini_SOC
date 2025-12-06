#!/usr/bin/env bash
set -Eeuo pipefail

############################################
# Mini SOC full pipeline runner
# Zeek JSON logs -> Filebeat -> Elasticsearch -> Kibana
############################################

# -------- Config (adjust if you want) --------
COMPOSE_BASE="docker-compose.yml"
COMPOSE_SETUP="docker-compose-setup.yml"

ES_CONTAINERS=("docker-es01-1" "docker-es02-1" "docker-es03-1")
KIBANA_CONTAINER="docker-kibana-1"
FILEBEAT_CONTAINER="docker-filebeat-1"

ZEEK_PCAP_DIR="$(pwd)/zeek/pcap"
ZEEK_LOG_DIR="$(pwd)/zeek/logs"
PCAP_FILE="$ZEEK_PCAP_DIR/sample.pcap"

# How long to sleep between health checks
SLEEP_INTERVAL=3
# Max attempts for health checks (attempts * interval)
MAX_ATTEMPTS=120

# -------- Helpers --------
log() {
  echo -e "\n[+] $*"
}

die() {
  echo -e "\n[!] ERROR: $*" >&2
  exit 1
}

run() {
  log "$*"
  "$@"
}

container_exists() {
  docker inspect "$1" >/dev/null 2>&1
}

container_health() {
  # returns: healthy | unhealthy | starting | nohealth | notfound
  local c="$1"
  if ! container_exists "$c"; then
    echo "notfound"
    return
  fi

  local has_health
  has_health="$(docker inspect -f '{{json .State.Health}}' "$c" 2>/dev/null || true)"
  if [[ -z "$has_health" || "$has_health" == "null" ]]; then
    echo "nohealth"
    return
  fi

  docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo "nohealth"
}

wait_container_running() {
  local c="$1"
  local i=0

  log "Waiting for container to be running: $c"
  while true; do
    if container_exists "$c"; then
      local status
      status="$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || true)"
      if [[ "$status" == "running" ]]; then
        echo "[+] $c is running."
        return 0
      fi
    fi

    ((i++)) || true
    if (( i >= MAX_ATTEMPTS )); then
      die "Container $c did not reach 'running' state."
    fi
    sleep "$SLEEP_INTERVAL"
  done
}

wait_container_healthy() {
  local c="$1"
  local i=0

  log "Waiting for container to be healthy: $c"
  while true; do
    local h
    h="$(container_health "$c")"

    case "$h" in
      healthy)
        echo "[+] $c is healthy."
        return 0
        ;;
      nohealth)
        # If no healthcheck is defined, fall back to "running"
        echo "[!] $c has no healthcheck. Falling back to running-state check."
        wait_container_running "$c"
        return 0
        ;;
      unhealthy)
        die "Container $c is unhealthy."
        ;;
      notfound)
        # container might not be created yet
        ;;
      *)
        # starting
        ;;
    esac

    ((i++)) || true
    if (( i >= MAX_ATTEMPTS )); then
      die "Container $c did not reach healthy state."
    fi
    sleep "$SLEEP_INTERVAL"
  done
}

require_file() {
  [[ -f "$1" ]] || die "Missing file: $1"
}

require_dir() {
  [[ -d "$1" ]] || die "Missing directory: $1"
}

# -------- Pre-checks --------
require_file "$COMPOSE_BASE"
require_file "$COMPOSE_SETUP"
require_dir "$ZEEK_PCAP_DIR"
require_dir "$ZEEK_LOG_DIR"
require_file "$PCAP_FILE"

# -------- Pipeline --------

# 1) Clean all existing docker containers/volumes
run docker compose down -v --remove-orphans

# 2) Clean existing zeek log folders
log "Cleaning Zeek logs..."
rm -f "$ZEEK_LOG_DIR"/*.log || true

# 3) Generate certs
run docker compose -f "$COMPOSE_BASE" -f "$COMPOSE_SETUP" run --rm setup

# 4) Run ES
run docker compose -f "$COMPOSE_BASE" up -d es01 es02 es03

# 5) Wait ES healthy
for c in "${ES_CONTAINERS[@]}"; do
  wait_container_healthy "$c"
done

# 6) Set kibana password (and other system users)
run docker compose -f "$COMPOSE_BASE" -f "$COMPOSE_SETUP" run --rm setup-passwords

# 7) Run kibana
run docker compose -f "$COMPOSE_BASE" up -d kibana

# 8) Wait Kibana healthy
wait_container_healthy "$KIBANA_CONTAINER"

# 9) Run Zeek to generate zeek logs (JSON)
log "Generating Zeek JSON logs from PCAP..."
run docker run --rm \
  -v "$ZEEK_PCAP_DIR:/pcap" \
  -v "$ZEEK_LOG_DIR:/logs" \
  -w /logs \
  zeek/zeek \
  zeek -C -r "/pcap/$(basename "$PCAP_FILE")" \
  -e '@load policy/tuning/json-logs'

# 10) Basic sanity check on host logs
log "Host Zeek logs preview:"
ls -lh "$ZEEK_LOG_DIR" | sed -n '1,120p' || true
[[ -f "$ZEEK_LOG_DIR/conn.log" ]] || die "conn.log not generated on host."

# 11) Run filebeat
run docker compose -f "$COMPOSE_BASE" up -d --force-recreate filebeat

# 12) Wait Filebeat running (it may not have healthcheck)
wait_container_running "$FILEBEAT_CONTAINER"

# 13) Check data inside the filebeat container
log "Checking Zeek logs inside Filebeat container..."
run docker exec -it "$FILEBEAT_CONTAINER" sh -lc 'ls -lh /var/log/zeek'
run docker exec -it "$FILEBEAT_CONTAINER" sh -lc 'wc -l /var/log/zeek/conn.log'
run docker exec -it "$FILEBEAT_CONTAINER" sh -lc 'head -n 1 /var/log/zeek/conn.log'

log "Pipeline completed."
echo "[+] Next: Go Kibana -> Data Views -> create 'zeek-*' with @timestamp."

# 14) Load kibana dashboard
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
SO_FILE="${SO_FILE:-kibana/v1.0.ndjson}"

echo "[*] Importing Kibana saved objects..."

curl -sS -k \
  -u "elastic:elastic" \
  -H "kbn-xsrf: true" \
  -F "file=@${SO_FILE}" \
  "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
  | cat