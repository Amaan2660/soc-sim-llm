#!/bin/bash
set -e

SOC_SIM_DIR="$HOME/Desktop/soc-sim 2.0"
WAZUH_DIR="$HOME/Desktop/wazuh-docker/single-node"
MANAGER="single-node-wazuh.manager-1"

echo "🧹 Clearing raw logs..."
cd "$SOC_SIM_DIR"
rm -f data/raw_logs/* 2>/dev/null || true

echo "📁 Creating empty log files..."
mkdir -p data/raw_logs
touch data/raw_logs/web_logs.jsonl
touch data/raw_logs/auth_logs.jsonl
touch data/raw_logs/endpoint_logs.jsonl
touch data/raw_logs/network_logs.jsonl

echo "🚀 Starting Wazuh..."
cd "$WAZUH_DIR"
docker compose up -d

echo "⏳ Waiting for Wazuh manager container..."
until docker ps --format '{{.Names}}' | grep -q "^${MANAGER}$"; do
  sleep 2
done

echo "⏳ Waiting for Wazuh manager to become responsive..."
for i in {1..60}; do
  if docker exec "$MANAGER" test -f /var/ossec/logs/ossec.log; then
    break
  fi
  sleep 2
done

echo "⏳ Verifying SOC log files are configured in Wazuh..."
docker exec "$MANAGER" sh -c "
  grep -q '/soc_logs/web_logs.jsonl' /var/ossec/etc/ossec.conf &&
  grep -q '/soc_logs/auth_logs.jsonl' /var/ossec/etc/ossec.conf &&
  grep -q '/soc_logs/endpoint_logs.jsonl' /var/ossec/etc/ossec.conf &&
  grep -q '/soc_logs/network_logs.jsonl' /var/ossec/etc/ossec.conf
"

echo "⏳ Verifying Wazuh analysis service is running..."
for i in {1..60}; do
  if docker exec "$MANAGER" sh -c "ps aux | grep -q '[w]azuh-analysisd'"; then
    echo "✅ wazuh-analysisd is running."
    break
  fi

  if [ "$i" -eq 60 ]; then
    echo "❌ wazuh-analysisd did not start."
    docker exec "$MANAGER" tail -n 50 /var/ossec/logs/ossec.log || true
    exit 1
  fi

  sleep 2
done

echo "✅ Wazuh is ready."

cd "$SOC_SIM_DIR"

echo "📊 Starting dashboard..."
docker compose up -d --build dashboard

echo "🔄 Resetting dashboard session..."
RESET_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/reset || true)

if [ "$RESET_STATUS" = "200" ]; then
  echo "✅ Dashboard reset complete."
else
  echo "⚠️ Dashboard reset failed (HTTP $RESET_STATUS)."
fi

echo "⚡ Running generators..."
docker compose up --build web_generator auth_generator endpoint_generator network_generator

echo "⏳ Waiting for alerts to appear in the dashboard..."
for i in {1..30}; do
  ALERT_COUNT=$(curl -s http://localhost:8080/api/stats | python3 -c 'import sys, json; print(json.load(sys.stdin).get("total", 0))' 2>/dev/null || echo 0)

  if [ "$ALERT_COUNT" -gt 0 ] 2>/dev/null; then
    echo "✅ Alerts are now indexed and visible in the dashboard."
    break
  fi

  if [ "$i" -eq 30 ]; then
    echo "⚠️ No alerts appeared in the dashboard yet."
  fi

  sleep 2
done

echo "✅ Done."
echo "Custom dashboard: http://localhost:8080"
echo "Wazuh dashboard: https://localhost"