/*
 * Rule: API00-C
 * Source: task 1057 (follow-on to task 741)
 * Status: PASS - Should NOT trigger API00-C violation
 */

/*
 * Reason: task 741's shift-safety gate exempts `param << literal` on an
 * unsigned parameter when the literal is below the parameter's width --
 * unsigned wrap is defined and the only undefined case reaches the width.
 * The width lookup was an exact-string match, so a typedef'd unsigned
 * type (sqlite's `sqlite3_uint64`, hostap's `os_time_t`-adjacent aliases)
 * fell through to `None` and the site was kept as unchecked arithmetic.
 * Task 1057 wires the check through the shared resolve_typedef_chain
 * (task 736) so `sqlite3_uint64` -> `unsigned long long` -> width 64 -> a
 * literal `<< 8` is recognised as safe.
 */

typedef unsigned long long sqlite3_uint64;

sqlite3_uint64 shift_typedef(sqlite3_uint64 x)
{
    return x << 8;
}
