/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * `p` is block-scoped inside the loop body and only assigned when `i == 0`,
 * so on every later iteration it is read in its indeterminate just-declared
 * state at `if (p)`. This is a genuine violation and must still be
 * detected at the real read site.
 *
 * Before the fix, aurora-lint's flat (non-block-scoped) dataflow could leak this
 * variable's join state across the loop's back edge into the loop header,
 * which is a predecessor of the loop body -- so the bare declaration line
 * itself (`Foo *p;`), which is never a read, got flagged as "may be used
 * uninitialized" instead of (or in addition to) the actual read at
 * `if (p)`. See the companion fix in is_read_context (task 391).
 */

typedef struct Foo Foo;
Foo *alloc(void);
void use(Foo *f);

int bar(int n) {
    int i;
    for (i = 0; i < n; i++) {
        Foo *p;
        if (i == 0) {
            p = alloc();
        }
        if (p) {
            use(p);
        }
    }
    return 0;
}
