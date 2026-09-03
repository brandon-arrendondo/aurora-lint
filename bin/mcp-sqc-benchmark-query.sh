#!/bin/sh
# Loads this node's local-agent reader credential (see
# ../.env.sqc_bench_reader, gitignored) before launching the shared
# benchmarking_db query MCP server -- keeps this interactive session's
# DB identity separate from queue_worker.py's sqc_writer credential,
# without putting a plaintext DSN in .mcp.json.
set -a
. "$(dirname "$0")/../.env.sqc_bench_reader"
set +a
exec python3 /home/brandon/data-enterprise/benchmarking_db/mcp_servers/query_server.py
