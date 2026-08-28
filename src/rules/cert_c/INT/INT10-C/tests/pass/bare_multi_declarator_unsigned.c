/*
 * Rule: INT10-C
 * Source: task 570 regression
 * Status: PASS - Should NOT trigger INT10-C violation
 *
 * Bare (non-init) comma-separated declarators like `u32 size, hash;` were
 * silently dropped from the type map, so `size % N_HASH` was misflagged as
 * a potentially-signed modulo even though `size` is unsigned.
 */

typedef unsigned int u32;

unsigned int memsys3_hash(u32 i) {
  u32 size, hash;
  size = i / 4;
  hash = size % 61;
  return hash;
}
