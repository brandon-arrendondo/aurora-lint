/*
 * Rule: EXP33-C
 * Source: testcases (lua ldblib.c db_getlocal shape)
 * Status: PASS - Should NOT trigger EXP33-C violation.
 * Same idiom as fail/../pass/testcases_crossfile_checked_return_conditional_write.c,
 * but the guard's checked-return call is wrapped in a branch-hint macro the
 * same way lua's own callers write it: `if (l_unlikely(!getstack(...)))`.
 * Without unwrapping `l_unlikely` (which aurora-lint has no preprocessor to
 * expand), `parse_call_return_guard` would see a bare call to `l_unlikely`
 * instead of `getstack`, and the guard would go unrecognized -- exactly
 * what happened against the real ldblib.c `db_getlocal`/`db_setlocal`
 * before this fix (both call `lua_getstack` through this same
 * `l_unlikely(...)` wrapper).
 */

#define l_unlikely(x) (x)

struct debug_info {
    int i_ci;
};

static int getstack(int level, struct debug_info *ar) {
    int status;
    if (level < 0)
        return 0;
    if (level == 0) {
        status = 1;
        ar->i_ci = level;
    } else {
        status = 0;
    }
    return status;
}

static void reader(const struct debug_info *ar) {
    int x = ar->i_ci;
    (void)x;
}

void caller(int level) {
    struct debug_info ar;
    if (l_unlikely(!getstack(level, &ar)))
        return;
    reader(&ar);
}
