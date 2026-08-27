#!/usr/bin/env bash
# Post-merge sanity check for todo-sqlite-cli.db.
#
# The merge driver reconciles cross-node AUTOINCREMENT id collisions silently:
# it reports "N task(s) merged, 0 conflict(s)" while concatenating the
# colliding tasks' details bodies, unioning their tag sets, and leaving deps
# rows pointing at pre-renumber ids (see task 615).
#
# Run this after any merge that touched todo-sqlite-cli.db.
#
# Deliberately narrow. An earlier version also flagged "deps whose two tasks
# share no tag" and "pending task blocked by a done task" -- both turned out to
# be overwhelmingly legitimate (40+ hits, essentially all fine: tags are a bad
# relatedness proxy, and a satisfied dep on a done task is normal). Those
# checks were removed rather than kept as noise. What is left is the
# concatenation signature plus a precise list of the rows worth re-reading by
# hand, which is the only reliable check.
#
# A clean run is NOT proof the merge was correct -- only that the mechanical
# signatures are absent. Always re-read tasks you created yourself.
#
# Usage: scripts/todo_merge_audit.sh [since-git-ref] [db-path]
#   since-git-ref  compare against this ref to list recently-added tasks
#                  (default: ORIG_HEAD, which git sets to the pre-merge commit)

set -uo pipefail
SINCE="${1:-ORIG_HEAD}"
DB="${2:-todo-sqlite-cli.db}"

if [ ! -f "$DB" ]; then
    echo "error: no such db: $DB" >&2
    exit 1
fi

echo "=== todo-sqlite-cli.db merge audit: $DB ==="

# --- 1. Concatenation signature: one row holding two tasks' bodies. ----------
# A details body that repeats a section banner almost always means two bodies
# were spliced together.
echo
echo "--- [1] details body with a repeated section banner (splice signature) ---"
sqlite3 "$DB" "
  SELECT id, substr(title,1,55)
  FROM tasks
  WHERE details IS NOT NULL
    AND ( (length(details) - length(replace(details,'Checkpoint, not actionable work',''))) / 31 > 1
       OR (length(details) - length(replace(details,'Fix direction:','')))              / 14 > 1
       OR (length(details) - length(replace(details,'Actions:','')))                    /  8 > 1 );"

# --- 2. One task's body CONTAINED in another's -- the real splice signature. -
# This is the check that actually catches the failure. When the driver splices,
# the victim row becomes [other body] + [own body], while the renumbered task
# keeps [other body] alone. The two are therefore NOT equal, so an equality /
# GROUP BY details check misses it entirely (verified: it missed the real
# 611/614 corruption on 2026-08-27). Substring containment catches it.
echo
echo "--- [2] a task's details body CONTAINS another task's body (splice) ---"
sqlite3 -header "$DB" "
  SELECT a.id AS container, substr(a.title,1,32) AS container_title,
         b.id AS contained, substr(b.title,1,32) AS contained_title
  FROM tasks a JOIN tasks b
    ON a.id <> b.id
   AND b.details IS NOT NULL AND length(b.details) > 150
   AND a.details IS NOT NULL AND length(a.details) > length(b.details)
   AND instr(a.details, b.details) > 0;"

# --- 2b. Exactly-duplicated bodies. -----------------------------------------
# Weaker signal, kept because it is nearly free. Also surfaces genuine
# long-standing duplicate tasks (e.g. 109/110 from the pre-2026-04-20 import),
# which are harmless -- check created_at before acting.
echo
echo "--- [2b] identical details on 2+ tasks (check created_at before acting) ---"
sqlite3 -header "$DB" "
  SELECT group_concat(id) AS ids,
         group_concat(date(created_at)) AS created,
         substr(min(details),1,50) AS body
  FROM tasks
  WHERE details IS NOT NULL AND length(details) > 200
  GROUP BY details
  HAVING count(*) > 1;"

# --- 3. Rows to re-read by hand. --------------------------------------------
# Any task that appeared in the DB during this merge, plus anything it is
# gated on. These are the only rows where a silent renumber could have moved
# details/tags/deps under you.
echo
echo "--- [3] tasks added since $SINCE -- RE-READ THESE, plus their deps ---"
if git rev-parse --verify --quiet "$SINCE" >/dev/null 2>&1; then
    TMP="$(mktemp)"
    if git show "$SINCE:$DB" > "$TMP" 2>/dev/null; then
        OLD_MAX="$(sqlite3 "$TMP" 'SELECT COALESCE(MAX(id),0) FROM tasks;' 2>/dev/null || echo 0)"
        echo "(max task id at $SINCE was $OLD_MAX)"
        sqlite3 "$DB" "
          SELECT t.id, t.status,
                 COALESCE((SELECT group_concat(depends_on_id) FROM deps WHERE task_id=t.id),'-') AS deps,
                 substr(t.title,1,50)
          FROM tasks t WHERE t.id > $OLD_MAX ORDER BY t.id;"
    else
        echo "(no $DB at $SINCE -- skipping)"
    fi
    rm -f "$TMP"
else
    echo "(ref '$SINCE' not found -- pass one explicitly, e.g. scripts/todo_merge_audit.sh HEAD~1)"
fi

echo
echo "Hits are candidates, not confirmed corruption. Also re-check any task id"
echo "you wrote into prose or a commit message -- renumbering makes those stale."
