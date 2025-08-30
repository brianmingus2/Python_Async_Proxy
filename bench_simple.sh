#!/usr/bin/env bash
set -euo pipefail

PROXY_HOST=127.0.0.1
PROXY_PORT=8888
PROXY_USER=username
PROXY_PASS=password
TARGET_URL=http://127.0.0.1/

# Helper to build Proxy-Authorization header
AUTH_HEADER="Proxy-Authorization: Basic $(echo -n ${PROXY_USER}:${PROXY_PASS} | base64)"

echo "[*] Checking proxy metrics before benchmark"
curl -s http://${PROXY_HOST}:${PROXY_PORT}/metrics | jq .

echo "[*] Running wrk benchmark (30s, 8 threads, 256 connections)"
wrk -t8 -c256 -d30s -H "$AUTH_HEADER" -p http://${PROXY_HOST}:${PROXY_PORT} ${TARGET_URL}

echo "[*] Checking proxy metrics after benchmark"
curl -s http://${PROXY_HOST}:${PROXY_PORT}/metrics | jq .
