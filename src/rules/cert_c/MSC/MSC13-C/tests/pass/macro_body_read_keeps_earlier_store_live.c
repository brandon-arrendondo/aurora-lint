/*
 * Rule: MSC13-C
 * Status: PASS - the dead-store pass needs the macro-hidden-use rule too,
 * and needs it per statement rather than per function. `x` has an ordinary
 * read further down, so "is this variable read anywhere" says yes and the
 * unused-variable guard never fires -- but the FIRST store's only read is
 * inside EMIT_X()'s replacement list, and a statement-level identifier walk
 * sees a call with no arguments (task 756).
 */

void use(int);

#define EMIT_X() use(x)

void f(void)
{
    int x = 1;
    EMIT_X();
    x = 2;
    use(x);
}
