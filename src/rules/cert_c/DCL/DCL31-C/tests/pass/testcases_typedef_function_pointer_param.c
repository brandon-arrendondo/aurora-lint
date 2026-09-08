/*
 * Rule: DCL31-C
 * Source: task 1054 (sqlite delta-adjudication)
 * Status: PASS - Should NOT trigger DCL31-C violation
 */

/*
 * Reason: a parameter whose declared type is a typedef'd function pointer
 * (sqlite's `typedef int (*RecordCompare)(void *, int);` in sqliteInt.h,
 * used across src/btree.c and src/legacy.c) is directly callable by name
 * inside the function body. Its own declarator subtree carries no
 * function_declarator (it looks like an ordinary `Type name` parameter),
 * so the longhand-only detector (`function_pointer_param_names`) misses
 * it and the call reads as an undeclared function. Task 1054 wires the
 * shared typedef-chain resolver (task 736) into DCL31-C so this shape,
 * and the one-hop alias case (`typedef RecordCompare AliasedCompare`),
 * both resolve correctly.
 *
 * Real callers: src/btree.c:5957 (xRecordCompare, called at 5968/5975),
 * src/legacy.c:98 (xCallback, sqlite3_callback).
 */

typedef int (*RecordCompare)(void *a, int b);
typedef int (*sqlite3_callback)(void *cx, int argc, char **argv, char **cols);
typedef RecordCompare AliasedCompare;

static int call_direct(RecordCompare cmp, void *a, int b)
{
    return cmp(a, b);
}

static int call_via_alias(AliasedCompare cmp, void *a, int b)
{
    return cmp(a, b);
}

static int call_callback(sqlite3_callback cb, void *cx, int argc, char **argv, char **cols)
{
    return cb(cx, argc, argv, cols);
}
