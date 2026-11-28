/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * A struct or union the file never defines, as when its header is missing,
 * has no size the file can see: it may be a single byte. Adding a byte count
 * to a pointer to one is not known to scale twice, so it is not reported.
 * fail/scaled_integer_added_to_pointer_any_name.c reports the same addition
 * on a pointer to a struct the file defines.
 */

#include <stddef.h>

struct fwd;
union fwd_u;

struct fwd *next_fwd(struct fwd *p, size_t n) {
  return p + n * sizeof(int);
}

union fwd_u *next_fwd_u(union fwd_u *u, size_t n) {
  return u + n * sizeof(int);
}
