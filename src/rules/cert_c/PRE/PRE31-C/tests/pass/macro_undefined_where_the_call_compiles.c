/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the null macro is defined only where OMIT_UPSERT is, and the
 * code calling the name compiles only where it is not; there the name is
 * the function, which evaluates each argument once.
 */

struct upsert;
struct upsert *dup_list(int);

#ifndef OMIT_UPSERT
struct upsert *upsert_new(struct upsert *, int);
#else
#define upsert_new(a, b) ((struct upsert *)0)
#endif

#ifndef OMIT_UPSERT
struct upsert *upsert_dup(struct upsert *p, int n) {
    return upsert_new(dup_list(n), n++);
}
#endif
