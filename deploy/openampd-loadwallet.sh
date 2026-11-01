#!/bin/bash
# Idempotently load openampd's funding wallet on the node before openampd starts.
# The unit's EnvironmentFile gives OPENAMPD_RPC, OPENAMPD_RPCAUTH and
# OPENAMPD_WALLET. The credential goes to curl on its standard input (-K -),
# never as an argument: every user on the machine reads a command line.
auth=${OPENAMPD_RPCAUTH//\\/\\\\}; auth=${auth//\"/\\\"}   # escaped for curl's quoted config syntax
for i in $(seq 1 30); do
  r=$(printf 'user = "%s"\n' "$auth" | curl -s -K - \
        -d "{\"jsonrpc\":\"1.0\",\"method\":\"loadwallet\",\"params\":[\"$OPENAMPD_WALLET\"]}" "$OPENAMPD_RPC" 2>/dev/null)
  case "$r" in *'"name"'*|*[Aa]lready\ loaded*|*[Aa]lready\ exists*) exit 0;; esac
  sleep 2
done
exit 0
