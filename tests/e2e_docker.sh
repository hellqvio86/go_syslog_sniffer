#!/bin/bash
set -euo pipefail

# Build the docker image (unless SKIP_DOCKER_BUILD is set)
if [ -z "${SKIP_DOCKER_BUILD:-}" ]; then
  echo "Building Docker image..."
  docker build -t syslog_sniffer:latest .
else
  echo "Skipping Docker build (SKIP_DOCKER_BUILD is set)..."
fi

# Define variables
INTERFACE="lo"
PORT=5516
IMAGE_NAME="syslog_sniffer:latest"

echo "Starting sniffer container with 2s interval..."
rm -f sniffer_output_docker.txt

docker run --rm \
    --network host \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --user root \
    "$IMAGE_NAME" \
    --interface "$INTERFACE" --port "$PORT" --interval 2 > sniffer_output_docker.txt 2>&1 &
SNIFFER_PID=$!

# Start dummy listener on host
nc -u -l -p "$PORT" > /dev/null 2>&1 &
LISTENER_PID=$!

# Give it a moment to start
sleep 1

# Send a syslog message via UDP
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
echo "Generated Timestamp: $TIMESTAMP"
MESSAGE="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMAn application log entry..."
echo "Sending message: $MESSAGE"
echo -n "$MESSAGE" | nc -u -w 1 127.0.0.1 "$PORT"

# Wait for sniffer to finish (it should exit after 2s)
echo "Waiting for sniffer to finish..."
wait "$SNIFFER_PID" || true

# Kill listener
kill "$LISTENER_PID" 2>/dev/null || true

# Check output
echo "Checking output..."
cat sniffer_output_docker.txt

# Check for JSON structure and ABSENCE of logs
if grep -q "\"interval_seconds\": 2" sniffer_output_docker.txt && grep -q "\"mymachine.example.com\"" sniffer_output_docker.txt; then
  echo "SUCCESS: JSON Summary found and message captured!"
  if grep -q "DEBUG" sniffer_output_docker.txt; then
    echo "FAILURE: DEBUG logs found in JSON output (should be quiet)."
    exit 1
  else
    echo "SUCCESS: Output is quiet."
  fi
else
  echo "FAILURE: JSON Summary or message not found in output."
  exit 1
fi

rm -f sniffer_output_docker.txt
echo "E2E Docker test passed!"
