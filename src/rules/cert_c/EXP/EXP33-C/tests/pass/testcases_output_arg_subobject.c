/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. A FIELD or ELEMENT at a
 * known output-argument position -- `memset(u.space, 0, n)`, `memset(s.in.raw,
 * 0, n)`, `memset(grid[0], 0, n)`, `memset(rows[0].vals, 0, n)`,
 * `memset((vals), 0, n)` -- is storage the call FILLS, not content it reads.
 * The read predicate dispatched on the identifier's DIRECT parent, so the arm
 * that knows about output positions fired only for a bare identifier argument;
 * with a field access in between, sqlite's
 * `memset(uFts.tmpSpace, 0, sizeof(uFts.tmpSpace))` reported `uFts`
 * uninitialized at the very call that clears it (task 1037).
 *
 * Nothing here reads the object back afterwards, deliberately. Writing one
 * member does not make the whole object initialized -- `strcpy(emp.name, ...)`
 * must leave `emp.salary` reportable -- so the credit funnel is correctly
 * unchanged by this fix, and a read-back added here would be flagged for that
 * separate and legitimate reason.
 */
#include <string.h>

struct inner {
    int v;
    int raw[4];
};

struct outer {
    int len;
    struct inner in;
    int vals[4];
};

union frame {
    struct outer o;
    int space[16];
};

/* memset(var.field, ...) — the sqlite shape */
void union_field_output(void) {
    union frame u;

    memset(u.space, 0, sizeof(u.space));
}

/* memset(var.field.field, ...) */
void nested_field_output(void) {
    struct outer s;

    memset(s.in.raw, 0, sizeof(s.in.raw));
}

/* memset(var[i], ...) — the element itself is the whole argument */
void element_output(void) {
    int grid[4][8];

    memset(grid[0], 0, sizeof(grid[0]));
}

/* memset(var[i].field, ...) — a field reached through a subscript */
void field_element_output(void) {
    struct outer rows[2];

    memset(rows[0].vals, 0, sizeof(rows[0].vals));
}

/* memset((var), ...) — a redundant parenthesis must not hide the position */
void parenthesized_output(void) {
    int vals[8];

    memset((vals), 0, sizeof(vals));
}
