/*
 * Rule: INT10-C
 * Source: task-404 regression
 * Status: PASS - Should NOT trigger INT10-C violation
 *
 * Guards against a same-named-variable-across-functions type leak. The
 * rule's variable-to-type map must be scoped per function: `safe_mod`
 * declares local size_t variables `idx`/`size` and performs an unsigned,
 * always-safe modulo. A later, unrelated function reuses the names
 * `idx`/`size` as plain (signed) int parameters — with a whole-translation-
 * unit type map (no per-function scoping) that later, textually-last
 * declaration overwrites the earlier size_t entries, causing `safe_mod`'s
 * genuinely-safe modulo to be wrongly flagged as signed.
 */

size_t get_idx(void);
size_t get_size(void);

size_t safe_mod(void) {
  size_t idx = get_idx();
  size_t size = get_size();
  return (idx + 1) % size;
}

int helper(int idx, int size) {
  return idx + size;
}
