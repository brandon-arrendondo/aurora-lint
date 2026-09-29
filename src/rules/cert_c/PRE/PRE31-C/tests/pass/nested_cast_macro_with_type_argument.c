/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: cast(t, exp) expands to ((t)(exp)), a cast whenever t is a type
 * name: union GCUnion * here, passed directly or from inside another
 * macro's body (to_gc, str_of). Nothing is called and nothing is written,
 * so no argument has a side effect under either preset.
 */

#define cast(t, exp) ((t)(exp))
#define to_gc(o) cast(union GCUnion *, (o))
#define str_of(o) (&(to_gc(o))->s)
#define TWICE(x) ((x) + (x))

struct str { int len; };
union GCUnion { struct str s; int other; };

int length(void *o) {
    return TWICE(str_of(o)->len) + TWICE(cast(union GCUnion *, o)->other);
}
