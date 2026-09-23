/*
 * Rule: EXP33-C
 * Source: testcases (lua lua_getstack/lua_getlocal shape)
 * Status: PASS - Should NOT trigger EXP33-C violation.
 * `getstack` conditionally writes `*ar` (`ar->i_ci = level;`) and returns 1
 * on every path that wrote it, 0 on every path that didn't -- exactly lua's
 * `lua_getstack` in ldebug.c. That makes `getstack` a conditional writer
 * (`FunctionSummary::conditional_modifies_params`), so before this fix its
 * output stayed MaybeUninitialized regardless of what a caller's guard
 * proved. `caller`'s `if (!getstack(level, &ar)) return;` is exactly the
 * checked-return-value idiom that proves the write happened on the
 * surviving path -- getstack only returns non-zero along the path that
 * wrote `ar`. Without the return-value/write correlation proof,
 * `reader(&ar)` on that proven-initialized path still reported "may be used
 * uninitialized". Companion to fail/testcases_crossfile_readonly_deref.c.
 */

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
    if (!getstack(level, &ar))
        return;
    reader(&ar);
}
