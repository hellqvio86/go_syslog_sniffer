#!/bin/bash
set -euo pipefail

# Build the docker image (unless SKIP_DOCKER_BUILD is set)
if [ -z "${SKIP_DOCKER_BUILD:-}" ]; then
  echo "Building Docker image..."
  docker build -t syslog_sniffer:latest .
else
  echo "Skipping Docker build (SKIP_DOCKER_BUILD is set)..."
fi

echo "Starting sniffer container with periodic updates (frequency=2s)..."
rm -f sniffer_output_periodic.txt
docker rm -f sniffer_periodic_test_go >/dev/null 2>&1 || true

docker run --rm \
  --name sniffer_periodic_test_go \
  --network host \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  syslog_sniffer:latest \
  --interface lo \
  --port 5517 \
  --interval 12 \
  --periodic \
  --frequency 2 > sniffer_output_periodic.txt 2>&1 &

SNIFFER_PID=$!

# Start dummy listener on host
nc -u -l -p 5517 > /dev/null 2>&1 &
LISTENER_PID=$!

# Give container time to initialize socket
echo "Waiting for container to start..."
MAX_RETRIES=30
COUNT=0
while ! docker ps | grep -q sniffer_periodic_test_go; do
  if [ "$COUNT" -ge "$MAX_RETRIES" ]; then
    echo "Timed out waiting for container to start."
    kill "$LISTENER_PID" 2>/dev/null || true
    exit 1
  fi
  sleep 1
  COUNT=$((COUNT+1))
done

# Give application time to initialize socket
sleep 2

# Send first batch of messages
echo "Sending first batch of messages..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
MESSAGE1="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMFirst batch message"
for _ in {1..3}; do
  echo "$MESSAGE1" | nc -u -w 1 127.0.0.1 5517 > /dev/null 2>&1 || true
  sleep 0.2
done

# Wait for the first period to pass (frequency is 2s)
sleep 2.5

# Send second batch of messages
echo "Sending second batch of messages..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
MESSAGE2="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMSecond batch message"
for _ in {1..3}; do
  echo "$MESSAGE2" | nc -u -w 1 127.0.0.1 5517 > /dev/null 2>&1 || true
  sleep 0.2
done

# Wait for the second period to pass (frequency is 2s)
sleep 3

# Stop the container
docker stop sniffer_periodic_test_go > /dev/null 2>&1 || true
wait "$SNIFFER_PID" || true
kill "$LISTENER_PID" 2>/dev/null || true

echo "Checking output..."
cat sniffer_output_periodic.txt

# Verify we have multiple JSON objects
JSON_COUNT=$(grep -c "\"interval_seconds\":" sniffer_output_periodic.txt || true)

if [ "$JSON_COUNT" -ge 2 ]; then
  echo "SUCCESS: Found at least 2 periodic reports."
else
  echo "FAILURE: Expected at least 2 periodic reports, found $JSON_COUNT."
  exit 1
fi

# Verify content of messages
if grep -q "First batch message" sniffer_output_periodic.txt; then
  echo "SUCCESS: First batch message captured."
else
  echo "FAILURE: First batch message NOT found."
  exit 1
fi

if grep -q "Second batch message" sniffer_output_periodic.txt; then
  echo "SUCCESS: Second batch message captured."
else
  echo "FAILURE: Second batch message NOT found."
  exit 1
fi

echo "Periodic E2E test passed!"
rm -f sniffer_output_periodic.txt
