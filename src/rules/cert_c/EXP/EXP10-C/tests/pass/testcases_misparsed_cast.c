/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP10-C violation
 * Description: (u64)(expr) parses as a call to `u64` (tree-sitter cannot
 * tell a parenthesized typedef name from a callee), which used to count as
 * a second function call. sqlite util.c:706 / vdbemem.c:344 (task 1147
 * mechanism 4).
 */

typedef unsigned long long u64;
extern u64 msize(void *p);
extern int bit_set(u64 v, int n);

int f(void *p, int n, u64 out, int e1) {
  int ok = msize(p) >= (u64)(n + 1);
  out = (out & ~(u64)(1)) | ((u64)(1075 - e1) << 52);
  return ok + bit_set(out, 3);
}
