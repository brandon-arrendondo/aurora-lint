#!/bin/bash
# Bulk-load data/benchmarks.db into the Postgres schema from 01_schema.sql.
# Plan §4: parents before children, one CSV pass per table via `sqlite3 -csv`
# piped into `psql \copy` (never row-by-row INSERT -- at 24M rows the
# difference is hours). Run 01_schema.sql first; run 02_indexes.sql and
# 04_reset_sequences.sql after this succeeds.
#
# Connection is via standard libpq env vars -- set before running, e.g.:
#   export PGHOST=localhost PGUSER=sqc_migrate PGDATABASE=sqc_bench
#   export PGPASSWORD='...'
set -euo pipefail

SQLITE_DB="${1:-data/benchmarks.db}"

: "${PGHOST:?set PGHOST (or use libpq defaults)}"
: "${PGUSER:?set PGUSER}"
: "${PGDATABASE:?set PGDATABASE}"

# Parent-before-child order (plan §4 step 2).
TABLES=(
  runs
  cwe_scans
  violations
  cwe_metrics
  rule_cwe_breakdown
  realworld_runs
  realworld_results
  realworld_violations
  ground_truth
  audited_files
  audit_corpus_meta
  oracle_versions
)

for table in "${TABLES[@]}"; do
  sqlite_cols=$(sqlite3 "$SQLITE_DB" "PRAGMA table_info($table);" | wc -l)
  pg_cols=$(psql -X -A -t -c \
    "SELECT count(*) FROM information_schema.columns WHERE table_name = '$table';")
  if [ "$sqlite_cols" != "$pg_cols" ]; then
    echo "ABORT: $table column count mismatch (sqlite=$sqlite_cols pg=$pg_cols)" >&2
    echo "-- SELECT * column order must match the target table exactly; fix before loading." >&2
    exit 1
  fi

  n_rows=$(sqlite3 "$SQLITE_DB" "SELECT count(*) FROM $table;")
  echo "== $table: $n_rows rows =="

  sqlite3 "$SQLITE_DB" -csv -header "SELECT * FROM $table;" \
    | psql -X -c "\\copy $table FROM STDIN WITH (FORMAT csv, HEADER)"

  n_loaded=$(psql -X -A -t -c "SELECT count(*) FROM $table;")
  if [ "$n_loaded" != "$n_rows" ]; then
    echo "ABORT: $table row count mismatch after load (source=$n_rows loaded=$n_loaded)" >&2
    exit 1
  fi
  echo "== $table: verified $n_loaded rows loaded =="
done

echo "All tables loaded and row-count verified. Next: psql -f 02_indexes.sql && psql -f 04_reset_sequences.sql"
