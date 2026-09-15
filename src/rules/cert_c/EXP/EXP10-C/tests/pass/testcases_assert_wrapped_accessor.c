/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP10-C violation
 * Description: assert() and the GCC builtins only evaluate their operand,
 * so a macro built on them is as pure as that operand. Lua's
 * ivalue(o) -> check_exp(ttisinteger(o), val_(o).i) -> (lua_assert(c), (e))
 * with lua_assert(c) defined as assert(c), and seL4's likely(x) ->
 * __builtin_expect(!!(x), 1).
 */

#include <assert.h>

#define lua_assert(c) assert(c)
#define check_exp(c, e) (lua_assert(c), (e))
#define val_(o) ((o)->value_)
#define rawtt(o) ((o)->tt_)
#define checktag(o, t) (rawtt(o) == (t))
#define ttisinteger(o) checktag((o), 3)
#define ivalue(o) check_exp(ttisinteger(o), val_(o).i)
#define likely(x) __builtin_expect(!!(x), 1)

typedef struct { union { long i; } value_; int tt_; } TValue;
extern int read_flag(void);

int f(const TValue *t1, const TValue *t2) {
  if (ivalue(t1) == ivalue(t2)) return 1;
  return likely(read_flag()) + 2;
}
