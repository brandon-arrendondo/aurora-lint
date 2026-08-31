#!/usr/bin/env bash
# Bound the growth of target/ on a long-lived dev node.
#
# Debug builds accrete without limit: cargo writes a fresh session directory
# under target/debug/incremental on every edit-rebuild cycle and never
# garbage-collects the old ones, and target/debug/deps keeps artifacts for
# dependency versions and test binaries that no longer exist. Measured on a
# clean tree: `cargo build` alone leaves 868M (372M of it incremental);
# one `cargo test --no-run` on top takes it to 2.4G (1.6G incremental).
#
# This prunes, in escalating order, only when target/ is over the threshold:
#   1. target/debug/incremental  -- pure cache, always safe to delete
#   2. the whole dev profile     -- if still over after (1)
#
# target/release is NEVER touched. Benchmarks run against target/release/sqc
# and a run must not be disturbed mid-flight (see CLAUDE.md).
#
# Usage:  scripts/target-gc.sh [--dry-run]
# Env:    SQC_TARGET_GC_MAX_GB   threshold in GiB (default 4)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
max_gb="${SQC_TARGET_GC_MAX_GB:-4}"
dry_run=0
[[ "${1:-}" == "--dry-run" ]] && dry_run=1

log() { printf '%s target-gc: %s\n' "$(date -Is)" "$*"; }

size_gb() { du -sB1 "$1" 2>/dev/null | awk '{printf "%.2f", $1/1073741824}'; }

[[ -d "$target_dir" ]] || { log "no $target_dir; nothing to do"; exit 0; }

# Cargo takes an exclusive flock on target/<profile>/.cargo-lock for the
# duration of a build. Deleting artifacts under a running build corrupts it,
# so skip this pass rather than race it.
lock="$target_dir/debug/.cargo-lock"
if [[ -f "$lock" ]] && ! flock -n "$lock" true; then
  log "a cargo build holds $lock; skipping this pass"
  exit 0
fi

before="$(size_gb "$target_dir")"
if (( $(echo "$before < $max_gb" | bc -l) )); then
  log "${before}G < ${max_gb}G threshold; nothing to do"
  exit 0
fi

log "${before}G >= ${max_gb}G threshold; pruning"

prune() {
  if (( dry_run )); then log "would remove $1"; else rm -rf "$1"; fi
}

prune "$target_dir/debug/incremental"
after="$(size_gb "$target_dir")"
log "after incremental prune: ${after}G"

if (( $(echo "$after >= $max_gb" | bc -l) )); then
  log "still over threshold; cleaning the whole dev profile"
  if (( dry_run )); then
    log "would run: cargo clean --profile dev"
  else
    (cd "$repo_root" && cargo clean --profile dev)
  fi
  after="$(size_gb "$target_dir")"
fi

log "done: ${before}G -> ${after}G (release untouched)"
