#!/usr/bin/env bash
set -euo pipefail

PROXY_URL="http://127.0.0.1:8888"
AUTH="$(printf 'username:password' | base64 -w0)"
HDR="Proxy-Authorization: Basic ${AUTH}"

echo "[*] wrk warm-up"
wrk -t4 -c1000 -d10s --latency -H "$HDR" $PROXY_URL/index.html || true

echo "[*] wrk sustained"
wrk -t8 -c2000 -d30s --latency -H "$HDR" $PROXY_URL/index.html

echo "[*] pipelined (wrk lua)"
cat > /tmp/pipeline.lua <<'LUA'
wrk.method = "GET"
wrk.headers["Proxy-Authorization"] = "Basic ${AUTH}"
request = function()
  return wrk.format(nil, "/index.html")
end
LUA
wrk -t8 -c4000 -d30s -s /tmp/pipeline.lua --latency $PROXY_URL

echo "[*] siege check"
siege -c1000 -t30s --header="$HDR" $PROXY_URL/index.html
