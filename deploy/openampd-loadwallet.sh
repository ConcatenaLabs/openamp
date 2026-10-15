#!/bin/bash
# Idempotently load openampd funding wallet on node000 before openampd starts.
set -a; source /root/sequentia/openampd.env; set +a
for i in $(seq 1 30); do
  r=$(curl -s --user "$OPENAMPD_RPCAUTH" -d "{\"jsonrpc\":\"1.0\",\"method\":\"loadwallet\",\"params\":[\"$OPENAMPD_WALLET\"]}" "$OPENAMPD_RPC" 2>/dev/null)
  echo "$r" | grep -qiE "\"name\"|already loaded|already exists" && exit 0
  sleep 2
done
exit 0
