/*
 * Rule: PRE32-C
 * Source: aurora_lint 1284 (sqlite src/vdbeapi.c:1315)
 * Status: PASS - Should NOT trigger PRE32-C violation
 *
 * `SQLITE_DEBUG` here is the operand of #ifdef, not a function being called,
 * so there is no call whose arguments hold a directive. Inside an ERROR region
 * it reparses as a call taking the following source text as arguments.
 * See ADR-0008.
 */

struct Mem { int flags; };

struct Mem *nullMem(void)
{
    static struct Mem m = {
        0,
#ifdef SQLITE_DEBUG
        0,
#endif
    };
    return &m;
}
