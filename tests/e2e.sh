#!/bin/bash
set -euo pipefail

# Define variables
INTERFACE="lo"
PORT=5514
BINARY="./syslog_sniffer"

if [ ! -f "$BINARY" ]; then
  echo "Building binary..."
  go build -o syslog_sniffer main.go
fi

echo "Starting sniffer on $INTERFACE:$PORT with 2s interval..."
rm -f sniffer_output_e2e.txt

sudo "$BINARY" --interface "$INTERFACE" --port "$PORT" --interval 2 2>&1 | tee sniffer_output_e2e.txt &
SNIFFER_PID=$!

# Start dummy listener
nc -u -l -p "$PORT" > /dev/null 2>&1 &
LISTENER_PID=$!

sleep 0.5

# Send a syslog message via UDP
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
MESSAGE="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMAn application log entry..."
echo "Sending message: $MESSAGE"
echo -n "$MESSAGE" | nc -u -w 1 127.0.0.1 "$PORT"

# Wait for sniffer to finish
echo "Waiting for sniffer to finish..."
wait "$SNIFFER_PID" || true

# Kill listener
kill "$LISTENER_PID" 2>/dev/null || true

# Check output
echo "Checking output..."
cat sniffer_output_e2e.txt

if grep -q "\"interval_seconds\": 2" sniffer_output_e2e.txt && grep -q "\"mymachine.example.com\"" sniffer_output_e2e.txt; then
  echo "SUCCESS: JSON Summary found and message captured!"
  if grep -q "DEBUG" sniffer_output_e2e.txt; then
    echo "FAILURE: DEBUG logs found in JSON output (should be quiet)."
    exit 1
  fi
  echo "SUCCESS: Output is clean JSON."
else
  echo "FAILURE: JSON Summary or message not found in output."
  exit 1
fi

rm -f sniffer_output_e2e.txt
echo "E2E local test passed!"
