/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: ivalue expands through check_exp and an assert of a read-only
 * condition; nothing in the chain writes, so passing it to a macro that
 * evaluates k several times has no side effect.
 */

#include <assert.h>

#define lua_assert(c) assert(c)
#define check_exp(c, e) (lua_assert(c), (e))
#define val_(o) ((o)->value_)
#define ttisinteger(o) ((o)->tt == 3)
#define ivalue(o) check_exp(ttisinteger(o), val_(o).i)
#define fastgeti(t, k, res) \
    do { if ((k) < (t)->n) res = (t)->a[k]; else res = 0; } while (0)

struct V { int tt; struct { long i; } value_; };
struct T { long n; long *a; };

void f(struct T *t, struct V *rc) {
    long r;
    fastgeti(t, ivalue(rc), r);
    (void)r;
}
