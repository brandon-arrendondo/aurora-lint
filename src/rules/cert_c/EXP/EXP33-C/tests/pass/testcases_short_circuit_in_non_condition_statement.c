/*
 * Rule: EXP33-C
 * Source: testcases (task 460)
 * Status: PASS - Should NOT trigger EXP33-C violation
 * Description: a `&&`/`||` chain that writes an output parameter in its
 * first clause and reads it (guaranteed-safe by short-circuit evaluation)
 * in a later clause, but the chain itself is NOT an if/while/for condition
 * — it's embedded in a `return` statement or a declaration initializer.
 * The read-site query's "replay earlier clauses of an in-progress
 * short-circuited condition" path only fired when the enclosing statement
 * WAS the condition expression itself (as recorded for if/while/for), so a
 * chain embedded deeper inside a different statement kind fell through to
 * the block's pre-statement entry state, which didn't yet reflect the
 * first clause's write. Modeled on lua's lvm.c:592-598
 * (`luaV_flttointeger(fltvalue(t2), &i2, F2Ieq) && ivalue(t1) == i2`).
 */

int flttointeger(double n, long *p, int mode);

int equalobj_return(double t1, double t2) {
    long i2;
    return flttointeger(t2, &i2, 0) && (long)t1 == i2;
}

int equalobj_decl_init(double t1, double t2) {
    long i2;
    int ok = flttointeger(t2, &i2, 0) && (long)t1 == i2;
    return ok;
}
