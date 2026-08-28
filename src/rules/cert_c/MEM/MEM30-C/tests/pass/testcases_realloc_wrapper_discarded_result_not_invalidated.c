/*
 * Rule: MEM30-C
 * Source: lua ground-truth audit (task 563 regression)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Regression: a realloc-*named* wrapper whose result is a bare, discarded
 * statement (not `x = wrapper(old, n);`) is not the realloc-grow idiom --
 * mirrors lua's `luaD_reallocstack(lua_State *L, int newsize, int
 * raiseerror)`, which mutates state reachable from its first argument
 * in place rather than returning a new pointer to assign back. Treating
 * every REALLOC-named call as invalidating its first argument (task 563's
 * fix for hostap's os_realloc) wrongly marked `st` as a dangling pointer
 * with no reassignment ever able to clear it, false-flagging every later
 * read of `st` in the function.
 */

extern void *my_realloc_stack(void *st, int newsize, int raiseerror);

int grow_and_use(void *st, int newsize) {
    my_realloc_stack(st, newsize, 0);
    return st != 0; /* not a use-after-free: st was never actually freed here */
}
